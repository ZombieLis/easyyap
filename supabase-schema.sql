-- ════════════════════════════════════════════════════════
--  EASYYAP — SUPABASE DATABASE SCHEMA
--  Run this entire file in your Supabase SQL Editor
--  Dashboard → SQL Editor → New query → paste → Run
-- ════════════════════════════════════════════════════════

-- ── PROFILES ──────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.profiles (
  id            UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  email         TEXT,
  display_name  TEXT NOT NULL DEFAULT 'EasyYap User',
  avatar_color  TEXT NOT NULL DEFAULT '#5C6BC0',
  avatar_url    TEXT,
  created_at    TIMESTAMPTZ DEFAULT NOW(),
  updated_at    TIMESTAMPTZ DEFAULT NOW()
);

-- Auto-create a profile row whenever a new user signs up
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER AS $$
BEGIN
  INSERT INTO public.profiles (id, email, display_name)
  VALUES (
    NEW.id,
    NEW.email,
    COALESCE(split_part(NEW.email, '@', 1), 'EasyYap User')
  )
  ON CONFLICT (id) DO NOTHING;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

-- ── CONTACTS ──────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.contacts (
  id          BIGSERIAL PRIMARY KEY,
  owner_id    UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  contact_id  UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  created_at  TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(owner_id, contact_id)
);

-- ── INVITES ───────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.invites (
  id              BIGSERIAL PRIMARY KEY,
  code            TEXT UNIQUE NOT NULL,
  created_by      UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  invited_email   TEXT,
  invited_phone   TEXT,
  invitee_name    TEXT,
  expires_at      TIMESTAMPTZ NOT NULL,
  used            BOOLEAN DEFAULT FALSE,
  used_by         UUID REFERENCES public.profiles(id),
  created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- ── CHATS ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.chats (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name        TEXT,
  created_by  UUID REFERENCES public.profiles(id) ON DELETE SET NULL,
  created_at  TIMESTAMPTZ DEFAULT NOW(),
  updated_at  TIMESTAMPTZ DEFAULT NOW()
);

-- ── CHAT MEMBERS ──────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.chat_members (
  id        BIGSERIAL PRIMARY KEY,
  chat_id   UUID NOT NULL REFERENCES public.chats(id) ON DELETE CASCADE,
  user_id   UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  joined_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(chat_id, user_id)
);

-- ── MESSAGES ──────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.messages (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  chat_id     UUID NOT NULL REFERENCES public.chats(id) ON DELETE CASCADE,
  sender_id   UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  type        TEXT NOT NULL CHECK (type IN ('text','image','voice','gif')),
  text        TEXT,
  media_url   TEXT,
  duration    TEXT,
  created_at  TIMESTAMPTZ DEFAULT NOW()
);

-- Index for fast message fetching
CREATE INDEX IF NOT EXISTS messages_chat_created ON public.messages(chat_id, created_at DESC);
CREATE INDEX IF NOT EXISTS chat_members_user ON public.chat_members(user_id);

-- ════════════════════════════════════════════════════════
--  ROW LEVEL SECURITY (RLS)
--  Users can only see their own data
-- ════════════════════════════════════════════════════════

ALTER TABLE public.profiles     ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.contacts     ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.invites      ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.chats        ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.chat_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.messages     ENABLE ROW LEVEL SECURITY;

-- Profiles: anyone can read (needed for chat member display), only owner can write
CREATE POLICY "profiles_select_all"  ON public.profiles FOR SELECT USING (true);
CREATE POLICY "profiles_update_own"  ON public.profiles FOR UPDATE USING (auth.uid() = id);
CREATE POLICY "profiles_insert_own"  ON public.profiles FOR INSERT WITH CHECK (auth.uid() = id);

-- Contacts: only owner can see their contacts
CREATE POLICY "contacts_own" ON public.contacts FOR ALL USING (auth.uid() = owner_id);

-- Invites: creator can manage, anyone can read by code (for join page)
CREATE POLICY "invites_creator" ON public.invites FOR ALL USING (auth.uid() = created_by);
CREATE POLICY "invites_read_by_code" ON public.invites FOR SELECT USING (true);

-- Chats: only members can see a chat
CREATE POLICY "chats_members_only" ON public.chats FOR SELECT
  USING (
    EXISTS (
      SELECT 1 FROM public.chat_members
      WHERE chat_id = chats.id AND user_id = auth.uid()
    )
  );
CREATE POLICY "chats_insert" ON public.chats FOR INSERT WITH CHECK (auth.uid() = created_by);
CREATE POLICY "chats_update_creator" ON public.chats FOR UPDATE USING (auth.uid() = created_by);
CREATE POLICY "chats_delete_creator" ON public.chats FOR DELETE USING (auth.uid() = created_by);

-- Chat members: only members of the chat can see membership
CREATE POLICY "chat_members_visible" ON public.chat_members FOR SELECT
  USING (
    EXISTS (
      SELECT 1 FROM public.chat_members cm2
      WHERE cm2.chat_id = chat_members.chat_id AND cm2.user_id = auth.uid()
    )
  );
CREATE POLICY "chat_members_insert" ON public.chat_members FOR INSERT WITH CHECK (true);
CREATE POLICY "chat_members_delete" ON public.chat_members FOR DELETE
  USING (auth.uid() = user_id OR EXISTS (
    SELECT 1 FROM public.chats WHERE id = chat_id AND created_by = auth.uid()
  ));

-- Messages: only chat members can read/write
CREATE POLICY "messages_members_only" ON public.messages FOR SELECT
  USING (
    EXISTS (
      SELECT 1 FROM public.chat_members
      WHERE chat_id = messages.chat_id AND user_id = auth.uid()
    )
  );
CREATE POLICY "messages_insert" ON public.messages FOR INSERT
  WITH CHECK (
    auth.uid() = sender_id AND
    EXISTS (
      SELECT 1 FROM public.chat_members
      WHERE chat_id = messages.chat_id AND user_id = auth.uid()
    )
  );

-- ════════════════════════════════════════════════════════
--  REALTIME — enable live message delivery
-- ════════════════════════════════════════════════════════

-- Enable realtime on messages table (for live chat updates)
ALTER PUBLICATION supabase_realtime ADD TABLE public.messages;
ALTER PUBLICATION supabase_realtime ADD TABLE public.chat_members;

-- ════════════════════════════════════════════════════════
--  STORAGE BUCKET
--  Create this manually in Supabase Dashboard:
--  Storage → New bucket → Name: "easyyap-media" → Public: ON
-- ════════════════════════════════════════════════════════
-- (Storage buckets cannot be created via SQL — see setup guide)
