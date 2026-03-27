/**
 * Dependency Injection Container.
 *
 * Simple factory-based DI — no heavy IoC framework.
 * All dependencies are wired here, keeping the domain/application layers
 * free of infrastructure concerns.
 *
 * In Next.js, this module is evaluated once per worker process.
 * Singletons are safe here.
 */

import { db } from './persistence/db'
import { DrizzleUserRepository } from './repositories/DrizzleUserRepository'
import { DrizzleRefreshTokenRepository } from './repositories/DrizzleRefreshTokenRepository'
import { DrizzleOAuthAccountRepository } from './repositories/DrizzleOAuthAccountRepository'
import { DrizzleAuditLogRepository } from './repositories/DrizzleAuditLogRepository'
import { Argon2PasswordHasher } from './services/Argon2PasswordHasher'
import { JwtTokenGenerator } from './services/JwtTokenGenerator'
import { GoogleOAuthClient } from './services/GoogleOAuthClient'
import { RedisSessionCache } from './external/cache/RedisSessionCache'
import { ConsoleEmailService } from './external/email/ConsoleEmailService'
import { getEventBus } from '@/application/shared/EventBus'

// Authorization framework
import { DrizzleRoleRepository } from './authz/repositories/DrizzleRoleRepository'
import { DrizzleUserRoleRepository } from './authz/repositories/DrizzleUserRoleRepository'
import { DrizzleResourceRelationRepository } from './authz/repositories/DrizzleResourceRelationRepository'
import { RbacPolicy } from './authz/policies/RbacPolicy'
import { AbacPolicy } from './authz/policies/AbacPolicy'
import { PbacPolicy } from './authz/policies/PbacPolicy'
import { RebacPolicy } from './authz/policies/RebacPolicy'
import { PolicyDecisionPoint } from './authz/pdp/PolicyDecisionPoint'
import { PolicyInformationPoint } from './authz/pip/PolicyInformationPoint'
import { PolicyEnforcementPoint } from './authz/pep/PolicyEnforcementPoint'
import { PolicyAdministrationPoint } from './authz/pap/PolicyAdministrationPoint'
import { CheckPermissionUseCase } from '@/application/authz/usecases/CheckPermissionUseCase'
import { AssignRoleUseCase } from '@/application/authz/usecases/AssignRoleUseCase'
import { RevokeRoleUseCase } from '@/application/authz/usecases/RevokeRoleUseCase'

import { ResolveIdentityUseCase } from '@/application/auth/auth-methods/ResolveIdentityUseCase'
import { GetAvailableAuthMethodsUseCase } from '@/application/auth/auth-methods/GetAvailableAuthMethodsUseCase'
import { UnlinkOAuthAccountUseCase } from '@/application/auth/oauth/UnlinkOAuthAccountUseCase'
import { SignupUseCase } from '@/application/auth/signup/SignupUseCase'
import { LoginUseCase } from '@/application/auth/login/LoginUseCase'
import { LogoutUseCase } from '@/application/auth/logout/LogoutUseCase'
import { RefreshTokenUseCase } from '@/application/auth/refresh/RefreshTokenUseCase'
import { GoogleOAuthUseCase } from '@/application/auth/oauth/GoogleOAuthUseCase'
import { LinkOAuthAccountUseCase } from '@/application/auth/oauth/LinkOAuthAccountUseCase'
import { ChangePasswordUseCase } from '@/application/auth/password/ChangePasswordUseCase'
import { ForgotPasswordUseCase } from '@/application/auth/password/ForgotPasswordUseCase'
import { ResetPasswordUseCase } from '@/application/auth/password/ResetPasswordUseCase'
import { SetPasswordUseCase } from '@/application/auth/password/SetPasswordUseCase'
import { LogoutAllUseCase } from '@/application/auth/session/LogoutAllUseCase'
import { RevokeSessionUseCase } from '@/application/auth/session/RevokeSessionUseCase'
import { ListSessionsUseCase } from '@/application/auth/session/ListSessionsUseCase'
import { VerifyEmailUseCase } from '@/application/auth/verify/VerifyEmailUseCase'

// ---------------------------------------------------------------------------
// Environment validation
// ---------------------------------------------------------------------------

function requireEnv(name: string): string {
  const value = process.env[name]
  if (!value) throw new Error(`Missing required environment variable: ${name}`)
  return value
}

// ---------------------------------------------------------------------------
// Infrastructure singletons
// ---------------------------------------------------------------------------

function buildPeppers(): Record<number, string> {
  // Support multiple pepper versions for rotation
  // PEPPER_1=secret1 PEPPER_2=secret2 ... (current version = highest number)
  const peppers: Record<number, string> = {}
  for (let i = 1; i <= 10; i++) {
    const val = process.env[`PEPPER_${i}`]
    if (val) peppers[i] = val
  }
  if (Object.keys(peppers).length === 0) {
    throw new Error('At least one PEPPER_N environment variable must be set')
  }
  return peppers
}

// Lazy-initialized singletons
let _container: ReturnType<typeof buildContainer> | null = null

function buildContainer() {
  // Repositories
  const userRepo = new DrizzleUserRepository(db)
  const refreshTokenRepo = new DrizzleRefreshTokenRepository(db)
  const oauthAccountRepo = new DrizzleOAuthAccountRepository(db)
  const auditLogRepo = new DrizzleAuditLogRepository(db)

  // Authorization repositories
  const roleRepo = new DrizzleRoleRepository(db)
  const userRoleRepo = new DrizzleUserRoleRepository(db)
  const resourceRelationRepo = new DrizzleResourceRelationRepository(db)

  // Services
  const passwordHasher = new Argon2PasswordHasher(buildPeppers())

  const tokenService = new JwtTokenGenerator({
    privateKeyPem: requireEnv('JWT_PRIVATE_KEY').replace(/\\n/g, '\n'),
    publicKeyPem: requireEnv('JWT_PUBLIC_KEY').replace(/\\n/g, '\n'),
    issuer: requireEnv('JWT_ISSUER'),
    audience: requireEnv('JWT_AUDIENCE'),
    accessTokenExpirySeconds: Number(
      process.env.ACCESS_TOKEN_EXPIRY_SECONDS ?? '900',
    ), // 15 min default
    verificationTokenExpirySeconds: Number(
      process.env.VERIFICATION_TOKEN_EXPIRY_SECONDS ?? '3600',
    ), // 1 hour
  })

  const sessionCache = new RedisSessionCache(requireEnv('REDIS_URL'))

  // Authorization framework assembly: PAP → PIP → PDP → PEP
  const pap = new PolicyAdministrationPoint(roleRepo)

  const pip = new PolicyInformationPoint(
    userRoleRepo,
    // Thin Redis adapter — PIP only needs get()
    { get: (key: string) => sessionCache.redisGet(key) },
  )

  const pdp = new PolicyDecisionPoint([
    new PbacPolicy(),
    new AbacPolicy(),
    new RbacPolicy(roleRepo),
    new RebacPolicy(resourceRelationRepo),
  ])

  const authzService = new PolicyEnforcementPoint(pdp, pip)

  // Authorization use cases
  const checkPermissionUseCase = new CheckPermissionUseCase(
    userRepo,
    userRoleRepo,
    authzService,
  )

  const assignRoleUseCase = new AssignRoleUseCase(
    userRepo,
    roleRepo,
    userRoleRepo,
    auditLogRepo,
  )

  const revokeRoleUseCase = new RevokeRoleUseCase(
    userRepo,
    userRoleRepo,
    auditLogRepo,
  )

  const emailService = new ConsoleEmailService()
  // TODO: swap with SendGridEmailService, SESEmailService, etc.

  const googleClient = new GoogleOAuthClient({
    clientId: requireEnv('GOOGLE_CLIENT_ID'),
    clientSecret: requireEnv('GOOGLE_CLIENT_SECRET'),
  })

  const eventBus = getEventBus()

  const config = {
    baseUrl: requireEnv('NEXT_PUBLIC_BASE_URL'),
    rtExpiryDays: Number(process.env.REFRESH_TOKEN_EXPIRY_DAYS ?? '30'),
  }

  // Use cases
  const signupUseCase = new SignupUseCase(
    userRepo,
    refreshTokenRepo,
    passwordHasher,
    tokenService,
    sessionCache,
    emailService,
    auditLogRepo,
    eventBus,
    config,
  )

  const loginUseCase = new LoginUseCase(
    userRepo,
    refreshTokenRepo,
    passwordHasher,
    tokenService,
    auditLogRepo,
    eventBus,
    config,
  )

  const logoutUseCase = new LogoutUseCase(
    refreshTokenRepo,
    sessionCache,
    auditLogRepo,
  )

  const refreshTokenUseCase = new RefreshTokenUseCase(
    userRepo,
    refreshTokenRepo,
    tokenService,
    auditLogRepo,
    config,
  )

  const googleOAuthUseCase = new GoogleOAuthUseCase(
    userRepo,
    refreshTokenRepo,
    oauthAccountRepo,
    tokenService,
    sessionCache,
    googleClient,
    auditLogRepo,
    eventBus,
    { rtExpiryDays: config.rtExpiryDays, csrfStatePrefix: 'oauth:state:' },
  )

  const linkOAuthAccountUseCase = new LinkOAuthAccountUseCase(
    userRepo,
    oauthAccountRepo,
    googleClient,
    sessionCache,
    emailService,
    auditLogRepo,
    eventBus,
  )

  const changePasswordUseCase = new ChangePasswordUseCase(
    userRepo,
    refreshTokenRepo,
    passwordHasher,
    sessionCache,
    emailService,
    auditLogRepo,
    eventBus,
  )

  const forgotPasswordUseCase = new ForgotPasswordUseCase(
    userRepo,
    tokenService,
    emailService,
    auditLogRepo,
    config,
  )

  const resetPasswordUseCase = new ResetPasswordUseCase(
    userRepo,
    refreshTokenRepo,
    passwordHasher,
    tokenService,
    sessionCache,
    emailService,
    auditLogRepo,
    eventBus,
  )

  const setPasswordUseCase = new SetPasswordUseCase(
    userRepo,
    passwordHasher,
    auditLogRepo,
    eventBus,
  )

  const logoutAllUseCase = new LogoutAllUseCase(
    userRepo,
    refreshTokenRepo,
    sessionCache,
    auditLogRepo,
    eventBus,
  )

  const revokeSessionUseCase = new RevokeSessionUseCase(
    refreshTokenRepo,
    sessionCache,
    auditLogRepo,
    eventBus,
  )

  const listSessionsUseCase = new ListSessionsUseCase(refreshTokenRepo)

  const resolveIdentityUseCase = new ResolveIdentityUseCase(userRepo, oauthAccountRepo)

  const getAvailableAuthMethodsUseCase = new GetAvailableAuthMethodsUseCase(
    userRepo,
    oauthAccountRepo,
  )

  const unlinkOAuthAccountUseCase = new UnlinkOAuthAccountUseCase(
    userRepo,
    oauthAccountRepo,
    auditLogRepo,
    eventBus,
  )

  const verifyEmailUseCase = new VerifyEmailUseCase(
    userRepo,
    tokenService,
    auditLogRepo,
  )

  return {
    // Repositories (for direct use in special cases)
    userRepo,
    oauthAccountRepo,
    userRoleRepo,
    resourceRelationRepo,
    // Authorization framework
    authzService,
    pap,
    checkPermissionUseCase,
    assignRoleUseCase,
    revokeRoleUseCase,
    // Use cases
    signupUseCase,
    loginUseCase,
    logoutUseCase,
    refreshTokenUseCase,
    googleOAuthUseCase,
    linkOAuthAccountUseCase,
    changePasswordUseCase,
    forgotPasswordUseCase,
    resetPasswordUseCase,
    setPasswordUseCase,
    logoutAllUseCase,
    revokeSessionUseCase,
    listSessionsUseCase,
    verifyEmailUseCase,
    resolveIdentityUseCase,
    getAvailableAuthMethodsUseCase,
    unlinkOAuthAccountUseCase,
    // Services (for middleware use)
    tokenService,
    sessionCache,
  }
}

export function getContainer() {
  if (!_container) {
    _container = buildContainer()
  }
  return _container
}
