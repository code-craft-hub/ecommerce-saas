/**
 * DeviceParser — lightweight user-agent → human-readable device info.
 *
 * Deliberately avoids heavy UA parser libraries.  Pattern matching is
 * sufficient for the session list UX — we only need a recognizable label,
 * not forensic accuracy.
 */

export interface DeviceInfo {
  /** e.g. "Chrome on Windows", "Safari on iPhone", "Firefox on macOS" */
  label: string
  deviceType: 'desktop' | 'mobile' | 'tablet' | 'unknown'
  browser: string
  os: string
}

const MOBILE_RE = /Mobi|Android|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i
const TABLET_RE = /iPad|Tablet|PlayBook/i

function parseBrowser(ua: string): string {
  if (/Edg\//.test(ua)) return 'Edge'
  if (/OPR\/|Opera/.test(ua)) return 'Opera'
  if (/Chrome\//.test(ua) && !/Chromium/.test(ua)) return 'Chrome'
  if (/Chromium\//.test(ua)) return 'Chromium'
  if (/Firefox\//.test(ua)) return 'Firefox'
  if (/Safari\//.test(ua) && !/Chrome/.test(ua)) return 'Safari'
  if (/MSIE|Trident/.test(ua)) return 'Internet Explorer'
  return 'Unknown Browser'
}

function parseOS(ua: string): string {
  if (/Windows NT 10/.test(ua)) return 'Windows 11/10'
  if (/Windows NT 6/.test(ua)) return 'Windows'
  if (/Mac OS X/.test(ua)) {
    if (/iPhone/.test(ua)) return 'iOS'
    if (/iPad/.test(ua)) return 'iPadOS'
    return 'macOS'
  }
  if (/Android/.test(ua)) return 'Android'
  if (/Linux/.test(ua)) return 'Linux'
  if (/CrOS/.test(ua)) return 'ChromeOS'
  return 'Unknown OS'
}

export function parseDevice(userAgent: string | null): DeviceInfo {
  if (!userAgent) {
    return { label: 'Unknown device', deviceType: 'unknown', browser: 'Unknown', os: 'Unknown' }
  }

  const browser = parseBrowser(userAgent)
  const os = parseOS(userAgent)

  let deviceType: DeviceInfo['deviceType'] = 'desktop'
  if (TABLET_RE.test(userAgent)) {
    deviceType = 'tablet'
  } else if (MOBILE_RE.test(userAgent)) {
    deviceType = 'mobile'
  }

  return {
    label: `${browser} on ${os}`,
    deviceType,
    browser,
    os,
  }
}
