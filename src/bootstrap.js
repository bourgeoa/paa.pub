/**
 * First-run bootstrap: create user, containers, keypair, WebID, ACLs.
 *
 * Writes ACLs directly to TRIPLESTORE KV via CloudflareAdapter.put()
 * to bypass WAC (no ACLs exist yet on first run).
 */
import { hashPassword } from './auth/password.js';
import { generateRSAKeyPair } from './crypto/rsa.js';
import { iri, literal } from './rdf/ntriples.js';
import { PREFIXES } from './rdf/prefixes.js';
import { getUserConfig } from './config.js';
import { createUser, listUsers } from './users.js';

let bootstrapped = false;

/**
 * Ensure the system is bootstrapped. Idempotent.
 * @param {object} env
 * @param {object} config
 * @param {import('@s20e/adapters/cloudflare').CloudflareAdapter} storage
 */
export async function ensureBootstrapped(env, config, storage) {
  if (bootstrapped) return;

  const systemFlag = await env.APPDATA.get('system_initialized');
  const legacyFlag = await env.APPDATA.get('user_initialized');

  if (systemFlag === 'true') {
    // Check if domain changed since last bootstrap (or was never recorded)
    const storedDomain = await env.APPDATA.get('bootstrap_domain');
    if (storedDomain !== config.domain) {
      console.log(`Bootstrap domain mismatch: stored=${storedDomain} current=${config.domain}, re-bootstrapping all users`);
      const users = await listUsers(env.APPDATA);
      for (const user of users) {
        await bootstrapUser(env, config, user.username, storage);
      }
      await env.APPDATA.put('bootstrap_domain', config.domain);
    }
    // Ensure ACP policies exist (migration for pre-ACP installs)
    const users = await listUsers(env.APPDATA);
    for (const user of users) {
      await ensureAcpPolicies(env, config, user.username);
      await ensureTypeIndex(env, config, user.username, storage);
    }
    bootstrapped = true;
    return;
  }

  // Migration path: user_initialized exists but system_initialized does not
  if (legacyFlag === 'true') {
    console.log('Migrating from single-user to multi-user system');
    const adminUsername = config.adminUsername;

    // Create users_index from existing admin user
    const existingMeta = await env.APPDATA.get(`user_meta:${adminUsername}`);
    if (!existingMeta) {
      await env.APPDATA.put(`user_meta:${adminUsername}`, JSON.stringify({
        createdAt: new Date().toISOString(),
        isAdmin: true,
        disabled: false,
      }));
    }
    const existingIndex = await env.APPDATA.get('users_index');
    if (!existingIndex) {
      await env.APPDATA.put('users_index', JSON.stringify([{
        username: adminUsername,
        createdAt: new Date().toISOString(),
        isAdmin: true,
        disabled: false,
      }]));
    }

    // Generate server-wide OIDC keys if not present
    await ensureOidcKeys(env);

    // Ensure ACP and TypeIndex for admin
    await ensureAcpPolicies(env, config, adminUsername);
    await ensureTypeIndex(env, config, adminUsername, storage);

    await env.APPDATA.put('system_initialized', 'true');
    bootstrapped = true;
    return;
  }

  // First-ever run
  if (!config.adminPassword) {
    throw new Error('PAA_PASSWORD environment variable must be set');
  }

  const adminUsername = config.adminUsername;

  // Hash password and create admin user record
  const passwordHash = await hashPassword(config.adminPassword);
  await createUser(env.APPDATA, adminUsername, passwordHash, { isAdmin: true });

  // Bootstrap admin user's pod
  await bootstrapUser(env, config, adminUsername, storage);

  // Generate server-wide OIDC keys
  await ensureOidcKeys(env);

  // Mark as initialized and store the domain used
  await env.APPDATA.put('system_initialized', 'true');
  await env.APPDATA.put('bootstrap_domain', config.domain);
  bootstrapped = true;
}

/**
 * Bootstrap a single user's pod: containers, keypair, WebID profile, ACLs.
 * Does NOT create the user record or hash passwords.
 * @param {object} env
 * @param {object} globalConfig - global config from getConfig()
 * @param {string} username
 * @param {import('@s20e/adapters/cloudflare').CloudflareAdapter} storage
 */
export async function bootstrapUser(env, globalConfig, username, storage) {
  const userConfig = getUserConfig(globalConfig, username);
  const { baseUrl } = globalConfig;

  // Generate RSA keypair for ActivityPub (skip if already exists)
  let publicPem = await env.APPDATA.get(`ap_public_key:${username}`);
  if (!publicPem) {
    const keyPair = await generateRSAKeyPair();
    await env.APPDATA.put(`ap_private_key:${username}`, keyPair.privatePem);
    await env.APPDATA.put(`ap_public_key:${username}`, keyPair.publicPem);
    publicPem = keyPair.publicPem;
  }

  // Initialize empty AP collections and friends list (skip if already exists)
  if (!await env.APPDATA.get(`ap_followers:${username}`)) {
    await env.APPDATA.put(`ap_followers:${username}`, '[]');
    await env.APPDATA.put(`ap_following:${username}`, '[]');
    await env.APPDATA.put(`ap_outbox_index:${username}`, '[]');
    await env.APPDATA.put(`ap_inbox_index:${username}`, '[]');
    await env.APPDATA.put(`quota:${username}`, JSON.stringify({ usedBytes: 0 }));
  }
  if (!await env.APPDATA.get(`friends:${username}`)) {
    await env.APPDATA.put(`friends:${username}`, '[]');
  }

  // Create containers and their ACLs
  const containers = [
    `${baseUrl}/${username}/`,
    `${baseUrl}/${username}/profile/`,
    `${baseUrl}/${username}/public/`,
    `${baseUrl}/${username}/private/`,
    `${baseUrl}/${username}/settings/`,
  ];

  const webId = userConfig.webId;
  const rdf = PREFIXES.rdf;
  const ldp = PREFIXES.ldp;
  const acl = PREFIXES.acl;
  const foaf = PREFIXES.foaf;

  for (const containerIri of containers) {
    // Write container type triple
    const containerNt = `${iri(containerIri)} ${iri(rdf + 'type')} ${iri(ldp + 'BasicContainer')} .`;
    await storage.put(`doc:${containerIri}:${containerIri}`, containerNt);
    await storage.put(`idx:${containerIri}`, JSON.stringify({ subjects: [containerIri] }));

    // Write WAC ACL (for kernel compatibility)
    const isPublic = containerIri.endsWith('/public/');
    const isRoot = containerIri === `${baseUrl}/${username}/`;
    const aclNt = buildContainerAcl(containerIri, webId, isPublic || isRoot, acl, foaf);
    await storage.put(`acl:${containerIri}`, aclNt);

    // Write ACP policy — root defaults to private, public/ is public
    const acpMode = isPublic ? 'public' : 'private';
    await env.APPDATA.put(`acp:${containerIri}`, JSON.stringify({
      mode: acpMode, agents: [], inherit: true,
    }));
  }

  // Create WebID profile document
  const profileIri = `${baseUrl}/${username}/profile/card`;
  const profileNt = buildProfileNTriples(profileIri, webId, username, baseUrl, publicPem);
  await storage.put(`doc:${profileIri}:${webId}`, profileNt);

  // Document-level triples (foaf:PersonalProfileDocument)
  const profileDocNt = [
    `${iri(profileIri)} ${iri(rdf + 'type')} ${iri(foaf + 'PersonalProfileDocument')} .`,
    `${iri(profileIri)} ${iri(foaf + 'maker')} ${iri(webId)} .`,
    `${iri(profileIri)} ${iri(foaf + 'primaryTopic')} ${iri(webId)} .`,
  ].join('\n');
  await storage.put(`doc:${profileIri}:${profileIri}`, profileDocNt);
  await storage.put(`idx:${profileIri}`, JSON.stringify({ subjects: [webId, profileIri] }));

  // ACL + ACP for profile: public read
  const profileAcl = buildContainerAcl(profileIri, webId, true, acl, foaf);
  await storage.put(`acl:${profileIri}`, profileAcl);
  await env.APPDATA.put(`acp:${profileIri}`, JSON.stringify({
    mode: 'public', agents: [], inherit: false,
  }));

  // Add profile/card to profile/ container
  const profileContainerIri = `${baseUrl}/${username}/profile/`;
  const containsNt = `${iri(profileContainerIri)} ${iri(ldp + 'contains')} ${iri(profileIri)} .`;
  const existingDoc = await storage.get(`doc:${profileContainerIri}:${profileContainerIri}`);
  await storage.put(`doc:${profileContainerIri}:${profileContainerIri}`,
    (existingDoc || '') + '\n' + containsNt);

  // Create TypeIndex documents in settings/
  const solid = PREFIXES.solid;
  const settingsIri = `${baseUrl}/${username}/settings/`;
  const privateTypeIndexIri = `${settingsIri}privateTypeIndex`;
  const publicTypeIndexIri = `${settingsIri}publicTypeIndex`;

  const privateTypeIndexNt = [
    `${iri(privateTypeIndexIri)} ${iri(rdf + 'type')} ${iri(solid + 'TypeIndex')} .`,
    `${iri(privateTypeIndexIri)} ${iri(rdf + 'type')} ${iri(solid + 'UnlistedDocument')} .`,
  ].join('\n');
  await storage.put(`doc:${privateTypeIndexIri}:${privateTypeIndexIri}`, privateTypeIndexNt);
  await storage.put(`idx:${privateTypeIndexIri}`, JSON.stringify({ subjects: [privateTypeIndexIri] }));

  const publicTypeIndexNt = [
    `${iri(publicTypeIndexIri)} ${iri(rdf + 'type')} ${iri(solid + 'TypeIndex')} .`,
    `${iri(publicTypeIndexIri)} ${iri(rdf + 'type')} ${iri(solid + 'ListedDocument')} .`,
  ].join('\n');
  await storage.put(`doc:${publicTypeIndexIri}:${publicTypeIndexIri}`, publicTypeIndexNt);
  await storage.put(`idx:${publicTypeIndexIri}`, JSON.stringify({ subjects: [publicTypeIndexIri] }));

  // Add TypeIndex documents to settings/ container
  const settingsContainsNt = [
    `${iri(settingsIri)} ${iri(ldp + 'contains')} ${iri(privateTypeIndexIri)} .`,
    `${iri(settingsIri)} ${iri(ldp + 'contains')} ${iri(publicTypeIndexIri)} .`,
  ].join('\n');
  const existingSettings = await storage.get(`doc:${settingsIri}:${settingsIri}`);
  await storage.put(`doc:${settingsIri}:${settingsIri}`,
    (existingSettings || '') + '\n' + settingsContainsNt);
}

/**
 * Generate server-wide OIDC RSA keys if not already present.
 */
async function ensureOidcKeys(env) {
  const existing = await env.APPDATA.get('oidc_public_key');
  if (!existing) {
    const keyPair = await generateRSAKeyPair();
    await env.APPDATA.put('oidc_private_key', keyPair.privatePem);
    await env.APPDATA.put('oidc_public_key', keyPair.publicPem);
  }
}

function buildContainerAcl(resourceIri, webId, publicRead, acl, foaf) {
  const lines = [
    `${iri(resourceIri + '.acl#owner')} ${iri(acl + 'agent')} ${iri(webId)} .`,
    `${iri(resourceIri + '.acl#owner')} ${iri(acl + 'accessTo')} ${iri(resourceIri)} .`,
    `${iri(resourceIri + '.acl#owner')} ${iri(acl + 'default')} ${iri(resourceIri)} .`,
    `${iri(resourceIri + '.acl#owner')} ${iri(acl + 'mode')} ${iri(acl + 'Read')} .`,
    `${iri(resourceIri + '.acl#owner')} ${iri(acl + 'mode')} ${iri(acl + 'Write')} .`,
    `${iri(resourceIri + '.acl#owner')} ${iri(acl + 'mode')} ${iri(acl + 'Control')} .`,
    `${iri(resourceIri + '.acl#owner')} ${iri(PREFIXES.rdf + 'type')} ${iri(acl + 'Authorization')} .`,
  ];

  if (publicRead) {
    lines.push(
      `${iri(resourceIri + '.acl#public')} ${iri(acl + 'agentClass')} ${iri(foaf + 'Agent')} .`,
      `${iri(resourceIri + '.acl#public')} ${iri(acl + 'accessTo')} ${iri(resourceIri)} .`,
      `${iri(resourceIri + '.acl#public')} ${iri(acl + 'default')} ${iri(resourceIri)} .`,
      `${iri(resourceIri + '.acl#public')} ${iri(acl + 'mode')} ${iri(acl + 'Read')} .`,
      `${iri(resourceIri + '.acl#public')} ${iri(PREFIXES.rdf + 'type')} ${iri(acl + 'Authorization')} .`,
    );
  }

  return lines.join('\n');
}

/**
 * Ensure ACP policies exist for core containers (migration for pre-ACP installs).
 */
async function ensureAcpPolicies(env, config, username) {
  const { baseUrl } = config;
  const policies = [
    [`acp:${baseUrl}/${username}/`, { mode: 'private', agents: [], inherit: true }],
    [`acp:${baseUrl}/${username}/profile/`, { mode: 'public', agents: [], inherit: true }],
    [`acp:${baseUrl}/${username}/profile/card`, { mode: 'public', agents: [], inherit: false }],
    [`acp:${baseUrl}/${username}/public/`, { mode: 'public', agents: [], inherit: true }],
    [`acp:${baseUrl}/${username}/private/`, { mode: 'private', agents: [], inherit: true }],
    [`acp:${baseUrl}/${username}/settings/`, { mode: 'private', agents: [], inherit: true }],
  ];

  for (const [key, policy] of policies) {
    const existing = await env.APPDATA.get(key);
    if (!existing) {
      await env.APPDATA.put(key, JSON.stringify(policy));
    }
  }
}

/**
 * Ensure TypeIndex documents and profile references exist (migration for pre-TypeIndex installs).
 */
async function ensureTypeIndex(env, config, username, storage) {
  const { baseUrl } = config;
  const solid = PREFIXES.solid;
  const rdf = PREFIXES.rdf;
  const ldp = PREFIXES.ldp;
  const webId = `${baseUrl}/${username}/profile/card#me`;
  const profileIri = `${baseUrl}/${username}/profile/card`;
  const settingsIri = `${baseUrl}/${username}/settings/`;
  const privateTypeIndexIri = `${settingsIri}privateTypeIndex`;
  const publicTypeIndexIri = `${settingsIri}publicTypeIndex`;

  // Check if TypeIndex documents exist
  const privateIdx = await storage.get(`idx:${privateTypeIndexIri}`);
  if (!privateIdx) {
    const privateTypeIndexNt = [
      `${iri(privateTypeIndexIri)} ${iri(rdf + 'type')} ${iri(solid + 'TypeIndex')} .`,
      `${iri(privateTypeIndexIri)} ${iri(rdf + 'type')} ${iri(solid + 'UnlistedDocument')} .`,
    ].join('\n');
    await storage.put(`doc:${privateTypeIndexIri}:${privateTypeIndexIri}`, privateTypeIndexNt);
    await storage.put(`idx:${privateTypeIndexIri}`, JSON.stringify({ subjects: [privateTypeIndexIri] }));

    // Add to settings container
    const containNt = `${iri(settingsIri)} ${iri(ldp + 'contains')} ${iri(privateTypeIndexIri)} .`;
    const existingSettings = await storage.get(`doc:${settingsIri}:${settingsIri}`);
    if (existingSettings && !existingSettings.includes(privateTypeIndexIri)) {
      await storage.put(`doc:${settingsIri}:${settingsIri}`, existingSettings + '\n' + containNt);
    }
  }

  const publicIdx = await storage.get(`idx:${publicTypeIndexIri}`);
  if (!publicIdx) {
    const publicTypeIndexNt = [
      `${iri(publicTypeIndexIri)} ${iri(rdf + 'type')} ${iri(solid + 'TypeIndex')} .`,
      `${iri(publicTypeIndexIri)} ${iri(rdf + 'type')} ${iri(solid + 'ListedDocument')} .`,
    ].join('\n');
    await storage.put(`doc:${publicTypeIndexIri}:${publicTypeIndexIri}`, publicTypeIndexNt);
    await storage.put(`idx:${publicTypeIndexIri}`, JSON.stringify({ subjects: [publicTypeIndexIri] }));

    // Add to settings container
    const containNt = `${iri(settingsIri)} ${iri(ldp + 'contains')} ${iri(publicTypeIndexIri)} .`;
    const existingSettings = await storage.get(`doc:${settingsIri}:${settingsIri}`);
    if (existingSettings && !existingSettings.includes(publicTypeIndexIri)) {
      await storage.put(`doc:${settingsIri}:${settingsIri}`, existingSettings + '\n' + containNt);
    }
  }

  // Ensure profile has TypeIndex references
  const profileDoc = await storage.get(`doc:${profileIri}:${webId}`);
  if (profileDoc && !profileDoc.includes('privateTypeIndex')) {
    const typeIndexTriples = [
      `${iri(webId)} ${iri(solid + 'privateTypeIndex')} ${iri(privateTypeIndexIri)} .`,
      `${iri(webId)} ${iri(solid + 'publicTypeIndex')} ${iri(publicTypeIndexIri)} .`,
    ].join('\n');
    await storage.put(`doc:${profileIri}:${webId}`, profileDoc + '\n' + typeIndexTriples);
  }

  // Ensure profile has document-level triples (PersonalProfileDocument)
  const foaf = PREFIXES.foaf;
  const profileDocTriples = await storage.get(`doc:${profileIri}:${profileIri}`);
  if (!profileDocTriples) {
    const docNt = [
      `${iri(profileIri)} ${iri(rdf + 'type')} ${iri(foaf + 'PersonalProfileDocument')} .`,
      `${iri(profileIri)} ${iri(foaf + 'maker')} ${iri(webId)} .`,
      `${iri(profileIri)} ${iri(foaf + 'primaryTopic')} ${iri(webId)} .`,
    ].join('\n');
    await storage.put(`doc:${profileIri}:${profileIri}`, docNt);
    // Update idx to include both subjects
    const idx = await storage.get(`idx:${profileIri}`);
    if (idx) {
      const parsed = JSON.parse(idx);
      if (!parsed.subjects.includes(profileIri)) {
        parsed.subjects.push(profileIri);
        await storage.put(`idx:${profileIri}`, JSON.stringify(parsed));
      }
    }
  }
}

function buildProfileNTriples(profileIri, webId, username, baseUrl, publicPem) {
  const rdf = PREFIXES.rdf;
  const foaf = PREFIXES.foaf;
  const solid = PREFIXES.solid;
  const ldp = PREFIXES.ldp;
  const space = PREFIXES.space;
  const keyId = `${profileIri}#main-key`;

  return [
    `${iri(webId)} ${iri(rdf + 'type')} ${iri(foaf + 'Person')} .`,
    `${iri(webId)} ${iri(foaf + 'name')} ${literal(username)} .`,
    `${iri(webId)} ${iri(foaf + 'isPrimaryTopicOf')} ${iri(profileIri)} .`,
    `${iri(webId)} ${iri(solid + 'oidcIssuer')} ${iri(baseUrl)} .`,
    `${iri(webId)} ${iri(space + 'storage')} ${iri(baseUrl + '/' + username + '/')} .`,
    `${iri(webId)} ${iri(ldp + 'inbox')} ${iri(baseUrl + '/' + username + '/inbox')} .`,
    `${iri(webId)} ${iri(solid + 'privateTypeIndex')} ${iri(baseUrl + '/' + username + '/settings/privateTypeIndex')} .`,
    `${iri(webId)} ${iri(solid + 'publicTypeIndex')} ${iri(baseUrl + '/' + username + '/settings/publicTypeIndex')} .`,
    // Security key for ActivityPub
    `${iri(keyId)} ${iri(rdf + 'type')} ${iri('https://w3id.org/security#Key')} .`,
    `${iri(keyId)} ${iri('https://w3id.org/security#owner')} ${iri(webId)} .`,
    `${iri(keyId)} ${iri('https://w3id.org/security#publicKeyPem')} ${literal(publicPem)} .`,
  ].join('\n');
}
