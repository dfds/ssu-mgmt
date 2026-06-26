<script setup lang="ts">
import HexMark from '../components/HexMark.vue';
import { useAuth } from '../auth/useAuth';
import { useTheme } from '../composables/useTheme';

const { displayName, email, roles, signOut } = useAuth();
const { toggle: toggleTheme } = useTheme();
</script>

<template>
  <div
    class="term"
    style="min-height:100vh;background:var(--t-bg);color:var(--t-text);display:flex;flex-direction:column"
  >
    <!-- header strip, echoing the console shell -->
    <header
      style="display:flex;align-items:center;height:46px;border-bottom:1px solid var(--t-line);background:var(--t-hdr);padding:0 16px;gap:9px"
    >
      <HexMark style="width:16px;height:16px;color:var(--color-brand)" />
      <span style="font-weight:700;letter-spacing:.06em">ssu-mgmt</span>
      <span style="flex:1"></span>
      <button
        type="button"
        title="toggle theme"
        style="background:none;border:1px solid var(--t-line2);color:var(--t-dim);font-family:inherit;font-size:11px;padding:2px 7px;cursor:pointer"
        @click="toggleTheme()"
      >
        theme
      </button>
    </header>

    <!-- centered access-denied card -->
    <main style="flex:1;display:flex;align-items:center;justify-content:center;padding:24px">
      <div style="width:100%;max-width:440px;background:var(--t-pane);border:1px solid var(--t-line)">
        <div
          style="display:flex;align-items:center;gap:8px;padding:9px 14px;border-bottom:1px solid var(--t-line)"
        >
          <span style="color:var(--t-red)">▌</span>
          <span style="font-weight:600;letter-spacing:.08em;font-size:11.5px">ACCESS&nbsp;DENIED</span>
          <span style="flex:1"></span>
          <span style="color:var(--t-faint);font-size:11px">403</span>
        </div>

        <div style="padding:18px 16px">
          <div style="color:var(--t-red);font-size:18px;font-weight:700;letter-spacing:.02em">Unauthorised</div>
          <p style="color:var(--t-dim);font-size:12.5px;line-height:1.6;margin:8px 0 0">
            You're signed in, but your account doesn't have the
            <span style="color:var(--t-text)">ce.cloudengineer</span> role required to use the console.
          </p>

          <div style="margin-top:16px;border:1px solid var(--t-line);background:var(--t-bg)">
            <div style="padding:8px 12px;border-bottom:1px solid var(--t-line)">
              <div
                style="color:var(--t-faint);font-size:10px;text-transform:uppercase;letter-spacing:.08em"
              >signed in as</div>
              <div style="color:var(--t-text);font-size:12.5px;margin-top:3px;overflow-wrap:anywhere">
                {{ displayName || email || 'unknown' }}
              </div>
              <div
                v-if="email && displayName"
                style="color:var(--t-dim);font-size:11px;margin-top:1px;overflow-wrap:anywhere"
              >{{ email }}</div>
            </div>
            <div style="padding:8px 12px">
              <div
                style="color:var(--t-faint);font-size:10px;text-transform:uppercase;letter-spacing:.08em;margin-bottom:6px"
              >roles</div>
              <div v-if="roles.length" style="display:flex;flex-wrap:wrap;gap:4px">
                <span
                  v-for="r in roles"
                  :key="r"
                  style="border:1px solid var(--t-line2);color:var(--t-dim);font-size:10.5px;padding:1px 6px;line-height:1.5;overflow-wrap:anywhere"
                >{{ r }}</span>
              </div>
              <div v-else style="color:var(--t-faint);font-size:11.5px;font-style:italic">no roles</div>
            </div>
          </div>

          <!-- actions -->
          <div style="margin-top:16px;display:flex;flex-wrap:wrap;gap:8px">
            <button
              type="button"
              style="background:var(--t-hdr);border:1px solid var(--t-line2);color:var(--t-text);font-family:inherit;font-size:12px;padding:7px 14px;cursor:pointer"
              @click="void signOut()"
            >
              sign out / switch account
            </button>
          </div>

          <p style="color:var(--t-faint);font-size:11px;line-height:1.6;margin:14px 0 0">
            If you believe you should have access, contact Cloud Engineering to be
            granted the <span style="color:var(--t-dim)">ce.cloudengineer</span> role.
          </p>
        </div>
      </div>
    </main>

    <!-- footer status line, console idiom -->
    <footer
      style="display:flex;align-items:center;height:26px;border-top:1px solid var(--t-line);background:var(--t-hdr);font-size:11px;color:var(--t-dim)"
    >
      <span
        style="background:var(--t-red);color:var(--t-bg);font-weight:700;padding:0 9px;height:100%;display:flex;align-items:center"
      >DENIED</span>
      <span style="padding:0 12px">prod-global · unauthorised</span>
    </footer>
  </div>
</template>
