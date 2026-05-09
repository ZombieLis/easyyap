require('dotenv').config();
const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const path = require('path');
const { createClient } = require('@supabase/supabase-js');

const app = express();
app.set('trust proxy', 1);
const PORT = process.env.PORT || 3000;

// ── Supabase admin client (service role — never expose to browser)
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY,
  { auth: { autoRefreshToken: false, persistSession: false } }
);

// ── Middleware
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, '../public')));

// Rate limiting — gentle, suited for elderly users retrying
const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 200 });
app.use('/api/', limiter);

// ── Auth middleware — verifies the Supabase JWT on protected routes
async function requireAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Not logged in' });
  }
  const token = auth.slice(7);
  const { data: { user }, error } = await supabase.auth.getUser(token);
  if (error || !user) return res.status(401).json({ error: 'Session expired — please log in again' });
  req.user = user;
  req.token = token;
  next();
}

// ════════════════════════════════════════════
//  AUTH ROUTES
// ════════════════════════════════════════════

// Send magic link
app.post('/api/auth/magic-link', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email is required' });

  const { error } = await supabase.auth.signInWithOtp({
    email: email.trim().toLowerCase(),
    options: {
      emailRedirectTo: `${process.env.APP_URL}/auth/callback`,
      shouldCreateUser: true,
    }
  });

  if (error) return res.status(400).json({ error: error.message });
  res.json({ ok: true, message: 'Magic link sent! Check your email 📧' });
});

// Verify OTP / exchange code for session (called after redirect)
app.post('/api/auth/verify', async (req, res) => {
  const { token_hash, type } = req.body;
  const { data, error } = await supabase.auth.verifyOtp({ token_hash, type: type || 'magiclink' });
  if (error) return res.status(400).json({ error: error.message });
  res.json({ session: data.session, user: data.user });
});

// ════════════════════════════════════════════
//  PROFILE ROUTES
// ════════════════════════════════════════════

// Get my profile
app.get('/api/profile', requireAuth, async (req, res) => {
  const { data, error } = await supabase
    .from('profiles')
    .select('*')
    .eq('id', req.user.id)
    .single();

  if (error && error.code !== 'PGRST116') return res.status(500).json({ error: error.message });

  // Auto-create profile if first login
  if (!data) {
    const newProfile = {
      id: req.user.id,
      email: req.user.email,
      display_name: req.user.email.split('@')[0],
      avatar_color: randomColor(),
      created_at: new Date().toISOString()
    };
    const { data: created, error: ce } = await supabase.from('profiles').insert(newProfile).select().single();
    if (ce) return res.status(500).json({ error: ce.message });
    return res.json(created);
  }
  res.json(data);
});

// Update my profile
app.patch('/api/profile', requireAuth, async (req, res) => {
  const { display_name, avatar_color, avatar_url } = req.body;
  const updates = {};
  if (display_name !== undefined) updates.display_name = display_name.trim().slice(0, 50);
  if (avatar_color !== undefined) updates.avatar_color = avatar_color;
  if (avatar_url !== undefined) updates.avatar_url = avatar_url;
  updates.updated_at = new Date().toISOString();

  const { data, error } = await supabase
    .from('profiles')
    .update(updates)
    .eq('id', req.user.id)
    .select()
    .single();

  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// Upload avatar (base64)
app.post('/api/profile/avatar', requireAuth, async (req, res) => {
  const { image_base64, mime_type } = req.body;
  if (!image_base64) return res.status(400).json({ error: 'No image provided' });

  const ext = mime_type === 'image/png' ? 'png' : 'jpg';
  const filename = `avatars/${req.user.id}.${ext}`;
  const buffer = Buffer.from(image_base64, 'base64');

  const { error: uploadError } = await supabase.storage
    .from('easyyap-media')
    .upload(filename, buffer, { contentType: mime_type || 'image/jpeg', upsert: true });

  if (uploadError) return res.status(500).json({ error: uploadError.message });

  const { data: urlData } = supabase.storage.from('easyyap-media').getPublicUrl(filename);

  await supabase.from('profiles').update({ avatar_url: urlData.publicUrl }).eq('id', req.user.id);
  res.json({ avatar_url: urlData.publicUrl });
});

// Search users by email (for inviting / finding contacts)
app.get('/api/users/search', requireAuth, async (req, res) => {
  const { q } = req.query;
  if (!q || q.length < 3) return res.json([]);

  const { data, error } = await supabase
    .from('profiles')
    .select('id, display_name, avatar_color, avatar_url, email')
    .ilike('email', `%${q}%`)
    .neq('id', req.user.id)
    .limit(10);

  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// ════════════════════════════════════════════
//  INVITE ROUTES
// ════════════════════════════════════════════

// Create an invite link
app.post('/api/invites', requireAuth, async (req, res) => {
  const { invited_email, invited_phone, invitee_name } = req.body;
  const { v4: uuidv4 } = require('uuid');
  const code = uuidv4().replace(/-/g, '').slice(0, 12);

  const invite = {
    code,
    created_by: req.user.id,
    invited_email: invited_email || null,
    invited_phone: invited_phone || null,
    invitee_name: invitee_name || null,
    expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(), // 7 days
    used: false
  };

  const { data, error } = await supabase.from('invites').insert(invite).select().single();
  if (error) return res.status(500).json({ error: error.message });

  const inviteUrl = `${process.env.APP_URL}/invite/${code}`;
  res.json({ ...data, invite_url: inviteUrl });
});

// Look up an invite by code (public — for the join page)
app.get('/api/invites/:code', async (req, res) => {
  const { data, error } = await supabase
    .from('invites')
    .select('*, profiles!invites_created_by_fkey(display_name, avatar_color)')
    .eq('code', req.params.code)
    .single();

  if (error || !data) return res.status(404).json({ error: 'Invite not found or expired' });
  if (data.used) return res.status(410).json({ error: 'This invite has already been used' });
  if (new Date(data.expires_at) < new Date()) return res.status(410).json({ error: 'This invite has expired' });

  res.json({
    invitee_name: data.invitee_name,
    invited_by: data.profiles?.display_name || 'Someone',
    invited_by_color: data.profiles?.avatar_color || '#5C6BC0',
    code: data.code
  });
});

// Mark invite as used (called after new user completes signup)
app.post('/api/invites/:code/accept', requireAuth, async (req, res) => {
  const { data: invite } = await supabase
    .from('invites')
    .select('*')
    .eq('code', req.params.code)
    .single();

  if (!invite) return res.status(404).json({ error: 'Invite not found' });

  // Mark used
  await supabase.from('invites').update({ used: true, used_by: req.user.id }).eq('code', req.params.code);

  // Auto-add as contacts (both ways)
  await supabase.from('contacts').upsert([
    { owner_id: invite.created_by, contact_id: req.user.id },
    { owner_id: req.user.id, contact_id: invite.created_by }
  ], { onConflict: 'owner_id,contact_id' });

  res.json({ ok: true, invited_by: invite.created_by });
});

// ════════════════════════════════════════════
//  CONTACTS ROUTES
// ════════════════════════════════════════════

app.get('/api/contacts', requireAuth, async (req, res) => {
  const { data, error } = await supabase
    .from('contacts')
    .select('contact_id, profiles!contacts_contact_id_fkey(id, display_name, avatar_color, avatar_url, email)')
    .eq('owner_id', req.user.id);

  if (error) return res.status(500).json({ error: error.message });
  res.json(data.map(r => r.profiles).filter(Boolean));
});

// ════════════════════════════════════════════
//  CHAT ROUTES
// ════════════════════════════════════════════

// Get all chats for current user
app.get('/api/chats', requireAuth, async (req, res) => {
  const { data, error } = await supabase
    .from('chat_members')
    .select(`
      chat_id,
      chats (
        id, name, created_at, created_by,
        messages ( id, text, type, created_at, sender_id )
      )
    `)
    .eq('user_id', req.user.id)
    .order('created_at', { referencedTable: 'chats', ascending: false });

  if (error) return res.status(500).json({ error: error.message });

  // Enrich with member profiles
  const chatIds = data.map(r => r.chat_id);
  const { data: members } = await supabase
    .from('chat_members')
    .select('chat_id, user_id, profiles!chat_members_user_id_fkey(id, display_name, avatar_color, avatar_url)')
    .in('chat_id', chatIds);

  const memberMap = {};
  (members || []).forEach(m => {
    if (!memberMap[m.chat_id]) memberMap[m.chat_id] = [];
    if (m.profiles) memberMap[m.chat_id].push(m.profiles);
  });

  const chats = data.map(r => ({
    ...r.chats,
    members: memberMap[r.chat_id] || [],
    last_message: (r.chats?.messages || []).sort((a, b) => new Date(b.created_at) - new Date(a.created_at))[0] || null,
    messages: undefined
  }));

  res.json(chats);
});

// Create a new chat
app.post('/api/chats', requireAuth, async (req, res) => {
  const { name, member_ids } = req.body;
  if (!member_ids || !member_ids.length) return res.status(400).json({ error: 'At least one member required' });

  const allMembers = [...new Set([req.user.id, ...member_ids])];

  const { data: chat, error } = await supabase
    .from('chats')
    .insert({ name: name || null, created_by: req.user.id })
    .select()
    .single();

  if (error) return res.status(500).json({ error: error.message });

  const memberRows = allMembers.map(uid => ({ chat_id: chat.id, user_id: uid }));
  await supabase.from('chat_members').insert(memberRows);

  res.json(chat);
});

// Update chat name
app.patch('/api/chats/:id', requireAuth, async (req, res) => {
  const { name } = req.body;
  const { data, error } = await supabase
    .from('chats')
    .update({ name })
    .eq('id', req.params.id)
    .select()
    .single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// Add member to chat
app.post('/api/chats/:id/members', requireAuth, async (req, res) => {
  const { user_id } = req.body;
  const { error } = await supabase
    .from('chat_members')
    .upsert({ chat_id: req.params.id, user_id }, { onConflict: 'chat_id,user_id' });
  if (error) return res.status(500).json({ error: error.message });
  res.json({ ok: true });
});

// Remove member from chat
app.delete('/api/chats/:id/members/:userId', requireAuth, async (req, res) => {
  const { error } = await supabase
    .from('chat_members')
    .delete()
    .eq('chat_id', req.params.id)
    .eq('user_id', req.params.userId);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ ok: true });
});

// Delete a chat (only creator can)
app.delete('/api/chats/:id', requireAuth, async (req, res) => {
  const { error } = await supabase
    .from('chats')
    .delete()
    .eq('id', req.params.id)
    .eq('created_by', req.user.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ ok: true });
});

// ════════════════════════════════════════════
//  MESSAGE ROUTES
// ════════════════════════════════════════════

// Get messages for a chat (paginated)
app.get('/api/chats/:id/messages', requireAuth, async (req, res) => {
  const limit = parseInt(req.query.limit) || 50;
  const before = req.query.before; // ISO timestamp for pagination

  let query = supabase
    .from('messages')
    .select('*, profiles!messages_sender_id_fkey(id, display_name, avatar_color, avatar_url)')
    .eq('chat_id', req.params.id)
    .order('created_at', { ascending: false })
    .limit(limit);

  if (before) query = query.lt('created_at', before);

  const { data, error } = await query;
  if (error) return res.status(500).json({ error: error.message });
  res.json(data.reverse()); // Return oldest-first
});

// Send a message
app.post('/api/chats/:id/messages', requireAuth, async (req, res) => {
  const { text, type, media_url, duration } = req.body;
  if (!type) return res.status(400).json({ error: 'Message type required' });

  const msg = {
    chat_id: req.params.id,
    sender_id: req.user.id,
    type: type || 'text',
    text: text || null,
    media_url: media_url || null,
    duration: duration || null,
    created_at: new Date().toISOString()
  };

  const { data, error } = await supabase.from('messages').insert(msg).select(
    '*, profiles!messages_sender_id_fkey(id, display_name, avatar_color, avatar_url)'
  ).single();

  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// Upload media (photo/voice) — base64
app.post('/api/chats/:id/media', requireAuth, async (req, res) => {
  const { image_base64, mime_type, filename } = req.body;
  if (!image_base64) return res.status(400).json({ error: 'No media provided' });

  const { v4: uuidv4 } = require('uuid');
  const ext = mime_type?.includes('audio') ? 'webm' : mime_type === 'image/png' ? 'png' : 'jpg';
  const path = `media/${req.params.id}/${uuidv4()}.${ext}`;
  const buffer = Buffer.from(image_base64, 'base64');

  const { error } = await supabase.storage
    .from('easyyap-media')
    .upload(path, buffer, { contentType: mime_type || 'image/jpeg' });

  if (error) return res.status(500).json({ error: error.message });

  const { data: urlData } = supabase.storage.from('easyyap-media').getPublicUrl(path);
  res.json({ url: urlData.publicUrl });
});

// ════════════════════════════════════════════
//  PAGE ROUTES (serve the frontend)
// ════════════════════════════════════════════

// Auth callback (magic link lands here)
app.get('/auth/callback', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/auth-callback.html'));
});

// Invite join page
app.get('/invite/:code', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/invite.html'));
});

// All other routes → main app
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/index.html'));
});

// ════════════════════════════════════════════
//  HELPERS
// ════════════════════════════════════════════

function randomColor() {
  const colors = ['#5C6BC0','#00897B','#E91E63','#F57C00','#1976D2','#388E3C','#7B1FA2','#D84315'];
  return colors[Math.floor(Math.random() * colors.length)];
}

app.listen(PORT, () => {
  console.log(`\n🟢 EasyYap server running on port ${PORT}`);
  console.log(`   Local: http://localhost:${PORT}\n`);
});
