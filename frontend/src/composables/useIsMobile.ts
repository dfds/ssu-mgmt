import { readonly, ref, type Ref } from 'vue';

const MOBILE_QUERY = '(max-width: 640px)';

const isMobile = ref<boolean>(
  typeof window !== 'undefined' && typeof window.matchMedia === 'function'
    ? window.matchMedia(MOBILE_QUERY).matches
    : false,
);

if (typeof window !== 'undefined' && typeof window.matchMedia === 'function') {
  const mql = window.matchMedia(MOBILE_QUERY);
  mql.addEventListener('change', (e) => {
    isMobile.value = e.matches;
  });
}

export function useIsMobile(): Readonly<Ref<boolean>> {
  return readonly(isMobile);
}
