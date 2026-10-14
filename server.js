const http = require('node:http');
const { readFile, rename, writeFile } = require('node:fs/promises');
const { randomBytes, randomUUID, scrypt, timingSafeEqual } = require('node:crypto');
const { promisify } = require('node:util');
const path = require('node:path');

const port = Number(process.env.PORT) || 3000;
const recordsPath = path.join(__dirname, 'data', 'records.json');
const usersPath = path.join(__dirname, 'data', 'users.json');
const attendanceStatuses = new Set(['Present', 'Absent', 'Late', 'Excused']);
const sessionLifetime = 7 * 24 * 60 * 60 * 1000;
const sessions = new Map();
const scryptAsync = promisify(scrypt);
let mutationQueue = Promise.resolve();
let userMutationQueue = Promise.resolve();

async function readRecords() {
  const content = await readFile(recordsPath, 'utf8');
  const records = JSON.parse(content);
  if (!Array.isArray(records)) throw new Error('The records store must contain a JSON array.');
  return records;
}

function mutateRecords(mutator) {
  const operation = mutationQueue.then(async () => {
    const records = await readRecords();
    const result = mutator(records);
    const temporaryPath = `${recordsPath}.${randomUUID()}.tmp`;
    await writeFile(temporaryPath, `${JSON.stringify(records, null, 2)}\n`, 'utf8');
    await rename(temporaryPath, recordsPath);
    return result;
  });
  mutationQueue = operation.catch(() => {});
  return operation;
}

async function readUsers() {
  const content = await readFile(usersPath, 'utf8');
  const users = JSON.parse(content);
  if (!Array.isArray(users)) throw new Error('The users store must contain a JSON array.');
  return users;
}

function mutateUsers(mutator) {
  const operation = userMutationQueue.then(async () => {
    const users = await readUsers();
    const result = mutator(users);
    const temporaryPath = `${usersPath}.${randomUUID()}.tmp`;
    await writeFile(temporaryPath, `${JSON.stringify(users, null, 2)}\n`, 'utf8');
    await rename(temporaryPath, usersPath);
    return result;
  });
  userMutationQueue = operation.catch(() => {});
  return operation;
}

function sendJson(response, statusCode, data, headers = {}) {
  response.writeHead(statusCode, { 'Content-Type': 'application/json; charset=utf-8', ...headers });
  response.end(data === null ? '' : JSON.stringify(data));
}

async function readJsonBody(request) {
  let body = '';
  for await (const chunk of request) {
    body += chunk;
    if (body.length > 1024 * 1024) {
      const error = new Error('Request body is too large.');
      error.statusCode = 413;
      throw error;
    }
  }
  try {
    return JSON.parse(body);
  } catch {
    const error = new Error('Request body must be valid JSON.');
    error.statusCode = 400;
    throw error;
  }
}

function validateStudent(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return 'A student object is required.';
  if (typeof value.name !== 'string' || !value.name.trim() || value.name.trim().length > 100) {
    return 'Student name is required and must be 100 characters or fewer.';
  }
  return null;
}

function validDate(value) {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
  const date = new Date(`${value}T00:00:00.000Z`);
  return !Number.isNaN(date.valueOf()) && date.toISOString().slice(0, 10) === value;
}

function publicUser(user) {
  return { id: user.id, email: user.email, role: user.role };
}

function sessionToken(request) {
  const cookie = request.headers.cookie || '';
  const pair = cookie.split(';').map(value => value.trim()).find(value => value.startsWith('session='));
  return pair ? pair.slice('session='.length) : null;
}

function currentUser(request) {
  const token = sessionToken(request);
  const session = token && sessions.get(token);
  if (!session) return null;
  if (session.expiresAt <= Date.now()) {
    sessions.delete(token);
    return null;
  }
  return session.user;
}

function createSession(response, user) {
  const token = randomBytes(32).toString('base64url');
  sessions.set(token, { user: publicUser(user), expiresAt: Date.now() + sessionLifetime });
  const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
  return { 'Set-Cookie': `session=${token}; HttpOnly; Path=/; SameSite=Strict; Max-Age=${sessionLifetime / 1000}${secure}` };
}

function authError(statusCode, message) {
  const error = new Error(message);
  error.statusCode = statusCode;
  return error;
}

async function handleAuthRequest(request, response, url) {
  if (url.pathname === '/api/auth/me' && request.method === 'GET') {
    const user = currentUser(request);
    sendJson(response, user ? 200 : 401, user || { error: 'Authentication required.' });
    return true;
  }

  if (url.pathname === '/api/auth/logout' && request.method === 'POST') {
    const token = sessionToken(request);
    if (token) sessions.delete(token);
    sendJson(response, 204, null, { 'Set-Cookie': 'session=; HttpOnly; Path=/; SameSite=Strict; Max-Age=0' });
    return true;
  }

  if (!['/api/auth/register', '/api/auth/login'].includes(url.pathname)) return false;
  if (request.method !== 'POST') {
    sendJson(response, 405, { error: 'Method not allowed.' });
    return true;
  }

  const input = await readJsonBody(request);
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    sendJson(response, 400, { error: 'A JSON object is required.' });
    return true;
  }
  if (typeof input.email !== 'string' || input.email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(input.email.trim())) {
    sendJson(response, 400, { error: 'Enter a valid email address.' });
    return true;
  }
  if (typeof input.password !== 'string' || input.password.length < 8 || input.password.length > 128) {
    sendJson(response, 400, { error: 'Password must be between 8 and 128 characters.' });
    return true;
  }

  const email = input.email.trim().toLowerCase();
  if (url.pathname === '/api/auth/register') {
    const salt = randomBytes(16).toString('hex');
    const passwordHash = (await scryptAsync(input.password, salt, 64)).toString('hex');
    try {
      const user = await mutateUsers(users => {
        if (users.some(existing => existing.email === email)) {
          throw authError(409, 'An account with that email already exists.');
        }
        const created = {
          id: randomUUID(),
          email,
          salt,
          passwordHash,
          role: users.length === 0 ? 'teacher' : 'student',
          createdAt: new Date().toISOString()
        };
        users.push(created);
        return created;
      });
      sendJson(response, 201, publicUser(user), createSession(response, user));
    } catch (error) {
      if (error.statusCode) sendJson(response, error.statusCode, { error: error.message });
      else throw error;
    }
    return true;
  }

  const user = (await readUsers()).find(existing => existing.email === email);
  if (!user) {
    await scryptAsync(input.password, 'invalid-account-salt', 64);
    sendJson(response, 401, { error: 'Email or password is incorrect.' });
    return true;
  }
  const passwordHash = await scryptAsync(input.password, user.salt, 64);
  const savedHash = Buffer.from(user.passwordHash, 'hex');
  if (savedHash.length !== passwordHash.length || !timingSafeEqual(savedHash, passwordHash)) {
    sendJson(response, 401, { error: 'Email or password is incorrect.' });
    return true;
  }
  sendJson(response, 200, publicUser(user), createSession(response, user));
  return true;
}

async function handleApiRequest(request, response, url) {
  const isAttendance = url.pathname === '/api/attendance';
  const match = url.pathname.match(/^\/api\/students(?:\/([^/]+)(?:\/(attendance))?)?$/);
  if (!isAttendance && !match) return false;

  const user = currentUser(request);
  if (!user) {
    sendJson(response, 401, { error: 'Authentication required.' });
    return true;
  }

  if (isAttendance) {
    if (request.method !== 'GET') {
      sendJson(response, 405, { error: 'Attendance sheets are read-only at this route.' });
      return true;
    }
    const date = url.searchParams.get('date');
    if (!validDate(date)) {
      sendJson(response, 400, { error: 'A valid attendance date is required.' });
      return true;
    }
    const students = await readRecords();
    sendJson(response, 200, students.map(student => ({
      id: student.id,
      name: student.name,
      status: student.attendance?.[date] || 'Unmarked',
      updatedAt: student.updatedAt
    })));
    return true;
  }

  const id = match[1] ? decodeURIComponent(match[1]) : null;
  const attendanceUpdate = match[2] === 'attendance';
  if (request.method === 'GET' && !id) {
    sendJson(response, 200, await readRecords());
    return true;
  }
  if (request.method !== 'GET' && user.role !== 'teacher') {
    sendJson(response, 403, { error: 'Only teachers can change the class roster or attendance.' });
    return true;
  }

  if (request.method === 'POST' && !id) {
    const input = await readJsonBody(request);
    const validationError = validateStudent(input);
    if (validationError) {
      sendJson(response, 400, { error: validationError });
      return true;
    }
    const student = await mutateRecords(students => {
      const created = {
        id: randomUUID(),
        name: input.name.trim(),
        attendance: {},
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
      };
      students.push(created);
      return created;
    });
    sendJson(response, 201, student);
    return true;
  }

  if (request.method === 'PUT' && id && attendanceUpdate) {
    const input = await readJsonBody(request);
    if (!validDate(input?.date)) {
      sendJson(response, 400, { error: 'A valid attendance date is required.' });
      return true;
    }
    if (input.status !== 'Unmarked' && !attendanceStatuses.has(input.status)) {
      sendJson(response, 400, { error: 'Status must be Present, Absent, Late, Excused, or Unmarked.' });
      return true;
    }
    const student = await mutateRecords(students => {
      const existing = students.find(item => item.id === id);
      if (!existing) return null;
      existing.attendance ||= {};
      if (input.status === 'Unmarked') delete existing.attendance[input.date];
      else existing.attendance[input.date] = input.status;
      existing.updatedAt = new Date().toISOString();
      return { ...existing, status: input.status };
    });
    sendJson(response, student ? 200 : 404, student || { error: 'Student not found.' });
    return true;
  }

  if (request.method === 'PUT' && id && !attendanceUpdate) {
    const input = await readJsonBody(request);
    const validationError = validateStudent(input);
    if (validationError) {
      sendJson(response, 400, { error: validationError });
      return true;
    }
    const student = await mutateRecords(students => {
      const existing = students.find(item => item.id === id);
      if (!existing) return null;
      existing.name = input.name.trim();
      existing.updatedAt = new Date().toISOString();
      return existing;
    });
    sendJson(response, student ? 200 : 404, student || { error: 'Student not found.' });
    return true;
  }

  if (request.method === 'DELETE' && id && !attendanceUpdate) {
    const deleted = await mutateRecords(students => {
      const index = students.findIndex(student => student.id === id);
      if (index < 0) return false;
      students.splice(index, 1);
      return true;
    });
    sendJson(response, deleted ? 204 : 404, deleted ? null : { error: 'Student not found.' });
    return true;
  }

  if (request.method === 'GET' || (request.method === 'DELETE' && attendanceUpdate)) {
    sendJson(response, 405, { error: 'Method not allowed.' });
    return true;
  }

  if ((request.method === 'PUT' || request.method === 'DELETE') && id) {
    sendJson(response, 405, { error: 'Method not allowed.' });
    return true;
  }

  sendJson(response, 405, { error: 'Method not allowed.' });
  return true;
}

const server = http.createServer(async (request, response) => {
  const url = new URL(request.url, `http://${request.headers.host || 'localhost'}`);
  try {
    if (await handleAuthRequest(request, response, url)) return;
    if (await handleApiRequest(request, response, url)) return;
    if (request.method !== 'GET' || !['/', '/index.html'].includes(url.pathname)) {
      response.writeHead(404);
      response.end('Not found');
      return;
    }
    const page = await readFile(path.join(__dirname, 'public', 'index.html'));
    response.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    response.end(page);
  } catch (error) {
    sendJson(response, error.statusCode || 500, { error: error.statusCode ? error.message : 'Unable to process the request.' });
  }
});

server.listen(port, () => {
  console.log(`CRUD demo running at http://localhost:${port}`);
});