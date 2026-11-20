// Centralized Framework7 Notification helpers, so every page reports
// success/error the same way instead of mixing toast/dialog.alert/inline
// message blocks.
function show($f7, { icon, title, text, color, closeTimeout = 4000 }) {
  $f7.notification.create({
    icon: `<i class="icon f7-icons" style="color: var(${color})">${icon}</i>`,
    title,
    text,
    closeButton: true,
    closeTimeout,
  }).open();
}

export function notifySuccess($f7, text, title = 'Success') {
  show($f7, { icon: 'checkmark_alt_circle_fill', title, text, color: '--f7-color-green, #4cd964' });
}

export function notifyError($f7, text, title = 'Error') {
  show($f7, { icon: 'exclamationmark_triangle_fill', title, text, color: '--f7-color-red, #ff3b30' });
}

// For an action that technically succeeded but didn't do everything the
// user likely expected (e.g. applied locally only, not pushed anywhere
// remote) -- distinct from a plain success so it doesn't read as "all done".
export function notifyWarning($f7, text, title = 'Note') {
  show($f7, { icon: 'exclamationmark_triangle_fill', title, text, color: '--f7-color-orange, #ff9500', closeTimeout: 8000 });
}

// errorMessage normalizes a caught error to a display string, matching
// the "err instanceof ApiError ? err.message : fallback" pattern used
// throughout this app.
export function errorMessage(err, ApiError, fallback) {
  return err instanceof ApiError ? err.message : fallback;
}
