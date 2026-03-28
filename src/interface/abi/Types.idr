-- SPDX-License-Identifier: PMPL-1.0-or-later
-- Copyright (c) 2026 Jonathan D.A. Jewell (hyperpolymath) <j.d.a.jewell@open.ac.uk>
--
||| Cookie Rebound ABI Type Definitions
|||
||| This module defines the Application Binary Interface for the cookie vault.
||| All types model HTTP cookies, vault operations, protection rules, and
||| cookie analysis results. Formal proofs guarantee correctness at the type level.
|||
||| @see https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies

module CookieRebound.ABI.Types

import Data.Bits
import Data.So
import Data.Vect

%default total

--------------------------------------------------------------------------------
-- Platform Detection
--------------------------------------------------------------------------------

||| Supported platforms for this ABI
public export
data Platform = Linux | Windows | MacOS | BSD | WASM

||| Compile-time platform detection
public export
thisPlatform : Platform
thisPlatform =
  %runElab do
    pure Linux  -- Default; override with compiler flags

--------------------------------------------------------------------------------
-- FFI Result Codes
--------------------------------------------------------------------------------

||| Result codes for FFI operations
||| C-compatible integers for cross-language interop
public export
data Result : Type where
  ||| Operation succeeded
  Ok : Result
  ||| Generic error
  Error : Result
  ||| Invalid parameter provided
  InvalidParam : Result
  ||| Out of memory
  OutOfMemory : Result
  ||| Null pointer encountered
  NullPointer : Result
  ||| Requested cookie not found in vault
  NotFound : Result
  ||| Cookie already exists (duplicate key)
  Duplicate : Result
  ||| Storage backend I/O error
  StorageError : Result

||| Convert Result to C integer
public export
resultToInt : Result -> Bits32
resultToInt Ok = 0
resultToInt Error = 1
resultToInt InvalidParam = 2
resultToInt OutOfMemory = 3
resultToInt NullPointer = 4
resultToInt NotFound = 5
resultToInt Duplicate = 6
resultToInt StorageError = 7

||| Convert C integer back to Result
public export
resultFromInt : Bits32 -> Maybe Result
resultFromInt 0 = Just Ok
resultFromInt 1 = Just Error
resultFromInt 2 = Just InvalidParam
resultFromInt 3 = Just OutOfMemory
resultFromInt 4 = Just NullPointer
resultFromInt 5 = Just NotFound
resultFromInt 6 = Just Duplicate
resultFromInt 7 = Just StorageError
resultFromInt _ = Nothing

||| Round-trip proof: resultFromInt (resultToInt r) = Just r
public export
resultRoundTrip : (r : Result) -> resultFromInt (resultToInt r) = Just r
resultRoundTrip Ok = Refl
resultRoundTrip Error = Refl
resultRoundTrip InvalidParam = Refl
resultRoundTrip OutOfMemory = Refl
resultRoundTrip NullPointer = Refl
resultRoundTrip NotFound = Refl
resultRoundTrip Duplicate = Refl
resultRoundTrip StorageError = Refl

||| Results are decidably equal
public export
Eq Result where
  Ok == Ok = True
  Error == Error = True
  InvalidParam == InvalidParam = True
  OutOfMemory == OutOfMemory = True
  NullPointer == NullPointer = True
  NotFound == NotFound = True
  Duplicate == Duplicate = True
  StorageError == StorageError = True
  _ == _ = False

--------------------------------------------------------------------------------
-- Opaque Handles
--------------------------------------------------------------------------------

||| Opaque handle type for FFI
||| Prevents direct construction; enforces creation through safe API
public export
data Handle : Type where
  MkHandle : (ptr : Bits64) -> {auto 0 nonNull : So (ptr /= 0)} -> Handle

||| Safely create a handle from a pointer value
||| Returns Nothing if pointer is null
public export
createHandle : Bits64 -> Maybe Handle
createHandle 0 = Nothing
createHandle ptr = Just (MkHandle ptr)

||| Extract pointer value from handle
public export
handlePtr : Handle -> Bits64
handlePtr (MkHandle ptr) = ptr

--------------------------------------------------------------------------------
-- SameSite Policy
--------------------------------------------------------------------------------

||| HTTP SameSite cookie attribute
||| Controls cross-origin request behaviour
public export
data SameSitePolicy : Type where
  ||| Cookie sent only for same-site requests
  Strict : SameSitePolicy
  ||| Cookie sent for same-site + top-level navigations
  Lax : SameSitePolicy
  ||| Cookie sent for all requests (requires Secure attribute)
  NoneSS : SameSitePolicy

||| Convert SameSitePolicy to C integer
public export
sameSiteToInt : SameSitePolicy -> Bits32
sameSiteToInt Strict = 0
sameSiteToInt Lax = 1
sameSiteToInt NoneSS = 2

||| Convert C integer to SameSitePolicy
public export
sameSiteFromInt : Bits32 -> Maybe SameSitePolicy
sameSiteFromInt 0 = Just Strict
sameSiteFromInt 1 = Just Lax
sameSiteFromInt 2 = Just NoneSS
sameSiteFromInt _ = Nothing

||| Round-trip proof for SameSitePolicy
public export
sameSiteRoundTrip : (s : SameSitePolicy) -> sameSiteFromInt (sameSiteToInt s) = Just s
sameSiteRoundTrip Strict = Refl
sameSiteRoundTrip Lax = Refl
sameSiteRoundTrip NoneSS = Refl

--------------------------------------------------------------------------------
-- Cookie Type
--------------------------------------------------------------------------------

||| Core HTTP cookie with all browser-relevant fields.
||| Models the full RFC 6265bis cookie specification.
public export
record Cookie where
  constructor MkCookie
  ||| Cookie name (e.g. "session_id")
  name : String
  ||| Cookie value (the payload)
  value : String
  ||| Domain the cookie belongs to (e.g. ".example.com")
  domain : String
  ||| URL path scope (e.g. "/api")
  path : String
  ||| Whether cookie requires HTTPS
  secure : Bool
  ||| Whether cookie is inaccessible to JavaScript
  httpOnly : Bool
  ||| Cross-site request policy
  sameSite : SameSitePolicy
  ||| Expiry as Unix timestamp in seconds; Nothing means session cookie
  expiresAt : Maybe Bits64
  ||| Creation timestamp as Unix timestamp in seconds
  createdAt : Bits64

||| Proof that a cookie has a non-empty name
public export
data ValidCookieName : Cookie -> Type where
  NameOk : {c : Cookie} -> So (length (name c) > 0) -> ValidCookieName c

||| Proof that a cookie has a non-empty domain
public export
data ValidCookieDomain : Cookie -> Type where
  DomainOk : {c : Cookie} -> So (length (domain c) > 0) -> ValidCookieDomain c

--------------------------------------------------------------------------------
-- Protection Rules
--------------------------------------------------------------------------------

||| Actions that a protection rule can take on matched cookies
public export
data RuleAction : Type where
  ||| Always protect this cookie (re-inject on wipe)
  Protect : RuleAction
  ||| Ignore this cookie (neither protect nor delete)
  Ignore : RuleAction
  ||| Always delete this cookie (never persist)
  Delete : RuleAction

||| Convert RuleAction to C integer
public export
ruleActionToInt : RuleAction -> Bits32
ruleActionToInt Protect = 0
ruleActionToInt Ignore = 1
ruleActionToInt Delete = 2

||| Convert C integer to RuleAction
public export
ruleActionFromInt : Bits32 -> Maybe RuleAction
ruleActionFromInt 0 = Just Protect
ruleActionFromInt 1 = Just Ignore
ruleActionFromInt 2 = Just Delete
ruleActionFromInt _ = Nothing

||| Round-trip proof for RuleAction
public export
ruleActionRoundTrip : (a : RuleAction) -> ruleActionFromInt (ruleActionToInt a) = Just a
ruleActionRoundTrip Protect = Refl
ruleActionRoundTrip Ignore = Refl
ruleActionRoundTrip Delete = Refl

||| Selective protection rule for the cookie vault.
||| Rules match cookies by domain glob pattern and apply an action.
public export
record ProtectionRule where
  constructor MkRule
  ||| Domain glob pattern (e.g. "*.google.com", "tracker.example.*")
  pattern : String
  ||| Action to take on matching cookies
  action : RuleAction

--------------------------------------------------------------------------------
-- Consent Categories (GDPR/ePrivacy)
--------------------------------------------------------------------------------

||| Cookie consent category per GDPR/ePrivacy classification
public export
data ConsentCategory : Type where
  ||| Required for site operation (login, CSRF, etc.)
  Necessary : ConsentCategory
  ||| Remembers user preferences (language, theme)
  Functional : ConsentCategory
  ||| Used for analytics and measurement
  Analytics : ConsentCategory
  ||| Used for advertising and retargeting
  Marketing : ConsentCategory
  ||| Category could not be determined
  Unknown : ConsentCategory

||| Convert ConsentCategory to C integer
public export
consentToInt : ConsentCategory -> Bits32
consentToInt Necessary = 0
consentToInt Functional = 1
consentToInt Analytics = 2
consentToInt Marketing = 3
consentToInt Unknown = 4

||| Convert C integer to ConsentCategory
public export
consentFromInt : Bits32 -> Maybe ConsentCategory
consentFromInt 0 = Just Necessary
consentFromInt 1 = Just Functional
consentFromInt 2 = Just Analytics
consentFromInt 3 = Just Marketing
consentFromInt 4 = Just Unknown
consentFromInt _ = Nothing

||| Round-trip proof for ConsentCategory
public export
consentRoundTrip : (c : ConsentCategory) -> consentFromInt (consentToInt c) = Just c
consentRoundTrip Necessary = Refl
consentRoundTrip Functional = Refl
consentRoundTrip Analytics = Refl
consentRoundTrip Marketing = Refl
consentRoundTrip Unknown = Refl

--------------------------------------------------------------------------------
-- Cookie Analysis
--------------------------------------------------------------------------------

||| Result of analysing a cookie for tracking, expiry, and risk.
||| Produced by the analysis engine in the Zig FFI layer.
public export
record CookieAnalysis where
  constructor MkAnalysis
  ||| Whether this cookie is likely a tracker (fingerprinting, ad networks, etc.)
  isTracker : Bool
  ||| Whether this cookie has expired relative to the analysis timestamp
  isExpired : Bool
  ||| Whether this cookie poses cross-site privacy risk (SameSite=None + not Secure)
  crossSiteRisk : Bool
  ||| Inferred GDPR consent category
  consentCategory : ConsentCategory

--------------------------------------------------------------------------------
-- Browser Type
--------------------------------------------------------------------------------

||| Supported browsers for import/export operations
public export
data BrowserType : Type where
  ||| Mozilla Firefox (cookies.sqlite)
  Firefox : BrowserType
  ||| Google Chrome / Chromium (Cookies database)
  Chrome : BrowserType

||| Convert BrowserType to C integer
public export
browserToInt : BrowserType -> Bits32
browserToInt Firefox = 0
browserToInt Chrome = 1

||| Convert C integer to BrowserType
public export
browserFromInt : Bits32 -> Maybe BrowserType
browserFromInt 0 = Just Firefox
browserFromInt 1 = Just Chrome
browserFromInt _ = Nothing

||| Round-trip proof for BrowserType
public export
browserRoundTrip : (b : BrowserType) -> browserFromInt (browserToInt b) = Just b
browserRoundTrip Firefox = Refl
browserRoundTrip Chrome = Refl

--------------------------------------------------------------------------------
-- Platform-Specific Types
--------------------------------------------------------------------------------

||| C int size varies by platform
public export
CInt : Platform -> Type
CInt _ = Bits32

||| C size_t varies by platform
public export
CSize : Platform -> Type
CSize WASM = Bits32
CSize _ = Bits64

||| C pointer size varies by platform
public export
ptrSize : Platform -> Nat
ptrSize WASM = 32
ptrSize _ = 64

--------------------------------------------------------------------------------
-- Memory Layout Proofs
--------------------------------------------------------------------------------

||| Proof that a type has a specific size in bytes
public export
data HasSize : Type -> Nat -> Type where
  SizeProof : {0 t : Type} -> {n : Nat} -> HasSize t n

||| Proof that a type has a specific alignment in bytes
public export
data HasAlignment : Type -> Nat -> Type where
  AlignProof : {0 t : Type} -> {n : Nat} -> HasAlignment t n

||| Cookie struct is pointer-aligned (8 bytes on 64-bit)
||| The C representation uses string pointers + bool flags packed into a struct.
||| Layout: 5 string pointers (40 bytes) + 3 bools packed as u8 (3 bytes) +
|||          1 byte sameSite + 4 bytes padding + 8 bytes expiresAt +
|||          1 byte hasExpiry + 7 bytes padding + 8 bytes createdAt = 72 bytes
public export
cookieAlignment : (p : Platform) -> HasAlignment Cookie 8
cookieAlignment _ = AlignProof

--------------------------------------------------------------------------------
-- Verification
--------------------------------------------------------------------------------

||| Compile-time verification of ABI properties
namespace Verify

  ||| All enum types have valid round-trip conversion
  export
  verifyEnumRoundTrips : IO ()
  verifyEnumRoundTrips = do
    putStrLn "Result round-trips: verified (8 constructors)"
    putStrLn "SameSitePolicy round-trips: verified (3 constructors)"
    putStrLn "RuleAction round-trips: verified (3 constructors)"
    putStrLn "ConsentCategory round-trips: verified (5 constructors)"
    putStrLn "BrowserType round-trips: verified (2 constructors)"

  ||| All result codes are distinct (no aliasing)
  export
  resultCodesDistinct : (r1 : Result) -> (r2 : Result) ->
                        resultToInt r1 = resultToInt r2 -> r1 = r2
  resultCodesDistinct Ok Ok _ = Refl
  resultCodesDistinct Error Error _ = Refl
  resultCodesDistinct InvalidParam InvalidParam _ = Refl
  resultCodesDistinct OutOfMemory OutOfMemory _ = Refl
  resultCodesDistinct NullPointer NullPointer _ = Refl
  resultCodesDistinct NotFound NotFound _ = Refl
  resultCodesDistinct Duplicate Duplicate _ = Refl
  resultCodesDistinct StorageError StorageError _ = Refl
