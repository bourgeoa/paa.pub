/**
 * Admin user management.
 */
import { requireAdmin } from './middleware.js';
import { listUsers, getUser, disableUser, enableUser, setUserQuota, createUser, userExists } from '../users.js';
import { getUserStorageLimit } from '../users.js';
import { hashPassword } from '../auth/password.js';
import { bootstrapUser } from '../bootstrap.js';
import { RESERVED_NAMES } from '../config.js';
import { renderPage } from '../ui/shell.js';
import template from '../ui/templates/admin-users.html';

/**
 * GET /admin/users — user management list.
 */
export async function renderAdminUsers(reqCtx) {
  const authCheck = requireAdmin(reqCtx);
  if (authCheck) return authCheck;

  const { env, config } = reqCtx;
  const message = reqCtx.url.searchParams.get('message') || '';
  const error = reqCtx.url.searchParams.get('error') || '';

  const data = await buildUserListData(env, config);
  data.message = message;
  data.error = error;
  data.registrationClosed = config.registrationMode === 'closed';

  return renderPage('User Management', template, data, { user: reqCtx.user, nav: 'admin', config });
}

/**
 * POST /admin/users — handle user management actions.
 */
export async function handleAdminUserAction(reqCtx) {
  const authCheck = requireAdmin(reqCtx);
  if (authCheck) return authCheck;

  const { request, env, config } = reqCtx;
  const form = await request.formData();
  const action = form.get('action');
  const username = form.get('username') || '';

  switch (action) {
    case 'disable': {
      if (username && username !== config.adminUsername) {
        await disableUser(env.APPDATA, username);
        return redirect(`/admin/users?message=User ${username} disabled`);
      }
      return redirect('/admin/users?error=Cannot disable admin');
    }
    case 'enable': {
      if (username) {
        await enableUser(env.APPDATA, username);
        return redirect(`/admin/users?message=User ${username} enabled`);
      }
      return redirect('/admin/users');
    }
    case 'set_quota': {
      const quotaMb = parseInt(form.get('quota_mb') || '0', 10);
      if (username && quotaMb >= 0) {
        await setUserQuota(env.APPDATA, username, quotaMb * 1024 * 1024);
        return redirect(`/admin/users?message=Quota set for ${username}`);
      }
      return redirect('/admin/users');
    }
    case 'create_user': {
      const newUsername = (form.get('new_username') || '').trim().toLowerCase();
      const newPassword = form.get('new_password') || '';

      if (!newUsername || !/^[a-zA-Z0-9_-]+$/.test(newUsername)) {
        return redirect('/admin/users?error=Invalid username');
      }
      if (RESERVED_NAMES.has(newUsername)) {
        return redirect('/admin/users?error=Username is reserved');
      }
      if (await userExists(env.APPDATA, newUsername)) {
        return redirect('/admin/users?error=Username already taken');
      }
      if (newPassword.length < 8) {
        return redirect('/admin/users?error=Password must be at least 8 characters');
      }

      const passwordHash = await hashPassword(newPassword);
      await createUser(env.APPDATA, newUsername, passwordHash);
      await bootstrapUser(env, config, newUsername, reqCtx.storage);

      return redirect(`/admin/users?message=User ${newUsername} created`);
    }
    default:
      return redirect('/admin/users');
  }
}

async function buildUserListData(env, config) {
  const userList = await listUsers(env.APPDATA);

  const users = await Promise.all(userList.map(async (u) => {
    const quotaData = await env.APPDATA.get(`quota:${u.username}`);
    const storageBytes = quotaData ? (JSON.parse(quotaData).usedBytes || 0) : 0;

    const userStorageLimit = await getUserStorageLimit(env.APPDATA, u.username, config.storageLimit);
    const quotaMb = Math.round(userStorageLimit / (1024 * 1024));

    return {
      username: u.username,
      isAdmin: u.isAdmin,
      disabled: u.disabled,
      storageDisplay: formatBytes(storageBytes),
      quotaDisplay: formatBytes(userStorageLimit),
      quotaMb,
    };
  }));

  return { users };
}

function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB'];
  const i = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  const val = bytes / Math.pow(1024, i);
  return `${val < 10 ? val.toFixed(1) : Math.round(val)} ${units[i]}`;
}

function redirect(location) {
  return new Response(null, { status: 302, headers: { 'Location': location } });
}
