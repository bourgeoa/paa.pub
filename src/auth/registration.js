/**
 * User registration: GET/POST /signup.
 */
import { renderPage } from '../ui/shell.js';
import { hashPassword } from './password.js';
import { createSession } from './session.js';
import { createUser, userExists } from '../users.js';
import { bootstrapUser } from '../bootstrap.js';
import { RESERVED_NAMES } from '../config.js';
import template from '../ui/templates/signup.html';

/**
 * GET /signup — render the registration form.
 */
export function renderSignupPage(reqCtx) {
  const { config } = reqCtx;
  if (config.registrationMode === 'closed') {
    return new Response('Registration is closed', { status: 403 });
  }
  const error = reqCtx.url.searchParams.get('error') || '';
  return renderPage('Sign Up', template, { error, username: '' });
}

/**
 * POST /signup — process registration.
 */
export async function handleSignup(reqCtx) {
  const { request, config, env } = reqCtx;

  if (config.registrationMode === 'closed') {
    return new Response('Registration is closed', { status: 403 });
  }

  const form = await request.formData();
  const username = (form.get('username') || '').trim().toLowerCase();
  const password = form.get('password') || '';
  const confirmPassword = form.get('confirm_password') || '';

  // Validate username
  if (!username || !/^[a-zA-Z0-9_-]+$/.test(username)) {
    return renderPage('Sign Up', template, {
      error: 'Username must contain only letters, numbers, hyphens, and underscores.',
      username,
    });
  }
  if (RESERVED_NAMES.has(username)) {
    return renderPage('Sign Up', template, {
      error: 'That username is reserved. Please choose another.',
      username,
    });
  }
  if (await userExists(env.APPDATA, username)) {
    return renderPage('Sign Up', template, {
      error: 'That username is already taken.',
      username,
    });
  }

  // Validate password
  if (password.length < 8) {
    return renderPage('Sign Up', template, {
      error: 'Password must be at least 8 characters.',
      username,
    });
  }
  if (password !== confirmPassword) {
    return renderPage('Sign Up', template, {
      error: 'Passwords do not match.',
      username,
    });
  }

  // Create the user
  const passwordHash = await hashPassword(password);
  await createUser(env.APPDATA, username, passwordHash);

  // Bootstrap user pod (containers, keypair, WebID profile, ACLs, TypeIndex)
  await bootstrapUser(env, config, username, reqCtx.storage);

  // Auto-login: create session and redirect to dashboard
  const token = await createSession(env.APPDATA, username);
  return new Response(null, {
    status: 302,
    headers: {
      'Location': '/dashboard',
      'Set-Cookie': `session=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400${config.protocol === 'https' ? '; Secure' : ''}`,
      'Set-Login': 'logged-in',
    },
  });
}
