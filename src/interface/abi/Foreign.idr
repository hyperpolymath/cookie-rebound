-- SPDX-License-Identifier: PMPL-1.0-or-later
-- Copyright (c) 2026 Jonathan D.A. Jewell (hyperpolymath) <j.d.a.jewell@open.ac.uk>
--
||| Cookie Rebound Foreign Function Interface Declarations
|||
||| This module declares all C-compatible functions implemented in the Zig FFI layer.
||| Each function has a primitive FFI binding and a safe wrapper that enforces
||| handle validity and error propagation through the Idris2 type system.
|||
||| The Zig implementation lives in src/interface/ffi/src/main.zig.
||| All types and layouts must match CookieRebound.ABI.Types.

module CookieRebound.ABI.Foreign

import CookieRebound.ABI.Types

%default total

--------------------------------------------------------------------------------
-- Library Lifecycle
--------------------------------------------------------------------------------

||| Initialize the cookie vault.
||| Opens or creates the persistent JSONL storage file.
||| Returns a handle to the vault instance, or null on failure.
export
%foreign "C:cookie_rebound_init, libcookie_rebound"
prim__init : PrimIO Bits64

||| Safe wrapper for vault initialization.
||| Returns Nothing if the vault could not be opened.
export
init : IO (Maybe Handle)
init = do
  ptr <- primIO prim__init
  pure (createHandle ptr)

||| Close the cookie vault and release all resources.
export
%foreign "C:cookie_rebound_free, libcookie_rebound"
prim__free : Bits64 -> PrimIO ()

||| Safe wrapper for vault cleanup.
export
free : Handle -> IO ()
free h = primIO (prim__free (handlePtr h))

--------------------------------------------------------------------------------
-- Cookie Storage Operations
--------------------------------------------------------------------------------

||| Store a cookie in the vault from a JSON string.
||| The JSON must contain: name, value, domain, path, secure, httpOnly,
||| sameSite, expiresAt (nullable), createdAt.
||| Returns a result code (0 = ok, see Result enum).
export
%foreign "C:cookie_rebound_store, libcookie_rebound"
prim__store : Bits64 -> String -> PrimIO Bits32

||| Safe wrapper: store a cookie from JSON representation.
export
store : Handle -> (cookieJson : String) -> IO Result
store h json = do
  code <- primIO (prim__store (handlePtr h) json)
  pure $ case resultFromInt code of
    Just r  => r
    Nothing => Error

||| Retrieve a cookie by domain and name.
||| Returns a JSON string pointer or null if not found.
export
%foreign "C:cookie_rebound_get, libcookie_rebound"
prim__get : Bits64 -> String -> String -> PrimIO Bits64

||| Free a string allocated by the library.
export
%foreign "C:cookie_rebound_free_string, libcookie_rebound"
prim__freeString : Bits64 -> PrimIO ()

||| Convert C string pointer to Idris String.
export
%foreign "support:idris2_getString, libidris2_support"
prim__getString : Bits64 -> String

||| Safe wrapper: retrieve a cookie as JSON by domain and name.
export
get : Handle -> (domain : String) -> (name : String) -> IO (Maybe String)
get h domain name = do
  ptr <- primIO (prim__get (handlePtr h) domain name)
  if ptr == 0
    then pure Nothing
    else do
      let str = prim__getString ptr
      primIO (prim__freeString ptr)
      pure (Just str)

||| List all cookies matching a domain filter.
||| Pass empty string to list all cookies.
||| Returns a JSON array string pointer or null on error.
export
%foreign "C:cookie_rebound_list, libcookie_rebound"
prim__list : Bits64 -> String -> PrimIO Bits64

||| Safe wrapper: list cookies for a domain filter (or all if empty).
export
list : Handle -> (domainFilter : String) -> IO (Maybe String)
list h domainFilter = do
  ptr <- primIO (prim__list (handlePtr h) domainFilter)
  if ptr == 0
    then pure Nothing
    else do
      let str = prim__getString ptr
      primIO (prim__freeString ptr)
      pure (Just str)

||| Delete a cookie from the vault by domain and name.
||| Returns a result code.
export
%foreign "C:cookie_rebound_delete, libcookie_rebound"
prim__delete : Bits64 -> String -> String -> PrimIO Bits32

||| Safe wrapper: delete a cookie by domain and name.
export
delete : Handle -> (domain : String) -> (name : String) -> IO Result
delete h domain name = do
  code <- primIO (prim__delete (handlePtr h) domain name)
  pure $ case resultFromInt code of
    Just r  => r
    Nothing => Error

--------------------------------------------------------------------------------
-- Protection Rules
--------------------------------------------------------------------------------

||| Add a protection rule from a JSON string.
||| JSON must contain: pattern (string), action ("protect"|"ignore"|"delete").
export
%foreign "C:cookie_rebound_add_rule, libcookie_rebound"
prim__addRule : Bits64 -> String -> PrimIO Bits32

||| Safe wrapper: add a protection rule from JSON.
export
addRule : Handle -> (ruleJson : String) -> IO Result
addRule h json = do
  code <- primIO (prim__addRule (handlePtr h) json)
  pure $ case resultFromInt code of
    Just r  => r
    Nothing => Error

||| Apply all protection rules to the vault.
||| Returns a JSON report of actions taken, or null on error.
export
%foreign "C:cookie_rebound_apply_rules, libcookie_rebound"
prim__applyRules : Bits64 -> PrimIO Bits64

||| Safe wrapper: apply rules and get a report.
export
applyRules : Handle -> IO (Maybe String)
applyRules h = do
  ptr <- primIO (prim__applyRules (handlePtr h))
  if ptr == 0
    then pure Nothing
    else do
      let str = prim__getString ptr
      primIO (prim__freeString ptr)
      pure (Just str)

--------------------------------------------------------------------------------
-- Cookie Analysis
--------------------------------------------------------------------------------

||| Analyse cookies for a given domain.
||| Returns a JSON analysis report or null on error.
export
%foreign "C:cookie_rebound_analyse, libcookie_rebound"
prim__analyse : Bits64 -> String -> PrimIO Bits64

||| Safe wrapper: analyse cookies for a domain.
export
analyse : Handle -> (domain : String) -> IO (Maybe String)
analyse h domain = do
  ptr <- primIO (prim__analyse (handlePtr h) domain)
  if ptr == 0
    then pure Nothing
    else do
      let str = prim__getString ptr
      primIO (prim__freeString ptr)
      pure (Just str)

--------------------------------------------------------------------------------
-- Browser Import/Export
--------------------------------------------------------------------------------

||| Export cookies from vault to a browser profile directory.
||| browserType: 0 = Firefox, 1 = Chrome
export
%foreign "C:cookie_rebound_export_browser, libcookie_rebound"
prim__exportBrowser : Bits64 -> Bits32 -> String -> PrimIO Bits32

||| Safe wrapper: export vault contents to a browser profile.
export
exportBrowser : Handle -> BrowserType -> (profilePath : String) -> IO Result
exportBrowser h browser profilePath = do
  code <- primIO (prim__exportBrowser (handlePtr h) (browserToInt browser) profilePath)
  pure $ case resultFromInt code of
    Just r  => r
    Nothing => Error

||| Import cookies from a browser profile directory into the vault.
||| browserType: 0 = Firefox, 1 = Chrome
export
%foreign "C:cookie_rebound_import_browser, libcookie_rebound"
prim__importBrowser : Bits64 -> Bits32 -> String -> PrimIO Bits32

||| Safe wrapper: import cookies from a browser profile.
export
importBrowser : Handle -> BrowserType -> (profilePath : String) -> IO Result
importBrowser h browser profilePath = do
  code <- primIO (prim__importBrowser (handlePtr h) (browserToInt browser) profilePath)
  pure $ case resultFromInt code of
    Just r  => r
    Nothing => Error

--------------------------------------------------------------------------------
-- Utility Functions
--------------------------------------------------------------------------------

||| Check if handle is initialized and vault is open.
export
%foreign "C:cookie_rebound_is_initialized, libcookie_rebound"
prim__isInitialized : Bits64 -> PrimIO Bits32

||| Safe wrapper: check initialization status.
export
isInitialized : Handle -> IO Bool
isInitialized h = do
  result <- primIO (prim__isInitialized (handlePtr h))
  pure (result /= 0)

||| Get library version string.
export
%foreign "C:cookie_rebound_version, libcookie_rebound"
prim__version : PrimIO Bits64

||| Get the library version.
export
version : IO String
version = do
  ptr <- primIO prim__version
  pure (prim__getString ptr)

||| Get last error message (or null if no error).
export
%foreign "C:cookie_rebound_last_error, libcookie_rebound"
prim__lastError : PrimIO Bits64

||| Retrieve last error as string.
export
lastError : IO (Maybe String)
lastError = do
  ptr <- primIO prim__lastError
  if ptr == 0
    then pure Nothing
    else pure (Just (prim__getString ptr))

--------------------------------------------------------------------------------
-- Error Descriptions
--------------------------------------------------------------------------------

||| Human-readable description for each result code.
export
errorDescription : Result -> String
errorDescription Ok = "Success"
errorDescription Error = "Generic error"
errorDescription InvalidParam = "Invalid parameter"
errorDescription OutOfMemory = "Out of memory"
errorDescription NullPointer = "Null pointer"
errorDescription NotFound = "Cookie not found"
errorDescription Duplicate = "Cookie already exists"
errorDescription StorageError = "Storage I/O error"
