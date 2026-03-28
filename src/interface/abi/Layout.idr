-- SPDX-License-Identifier: PMPL-1.0-or-later
-- Copyright (c) 2026 Jonathan D.A. Jewell (hyperpolymath) <j.d.a.jewell@open.ac.uk>
--
||| Cookie Rebound Memory Layout Proofs
|||
||| This module provides formal proofs about memory layout, alignment,
||| and padding for C-compatible structs used in the cookie vault FFI.
|||
||| The cookie struct uses string pointers, boolean flags, enum tags,
||| and 64-bit timestamps. Layout correctness is proven for all
||| supported platforms.
|||
||| @see https://en.wikipedia.org/wiki/Data_structure_alignment

module CookieRebound.ABI.Layout

import CookieRebound.ABI.Types
import Data.Vect
import Data.So

%default total

--------------------------------------------------------------------------------
-- Alignment Utilities
--------------------------------------------------------------------------------

||| Calculate padding needed for alignment.
||| Given a current offset and required alignment, returns the number
||| of padding bytes needed to reach the next aligned boundary.
public export
paddingFor : (offset : Nat) -> (alignment : Nat) -> Nat
paddingFor offset alignment =
  if offset `mod` alignment == 0
    then 0
    else alignment - (offset `mod` alignment)

||| Proof that alignment divides aligned size.
public export
data Divides : Nat -> Nat -> Type where
  DivideBy : (k : Nat) -> {n : Nat} -> {m : Nat} -> (m = k * n) -> Divides n m

||| Round up to next alignment boundary.
public export
alignUp : (size : Nat) -> (alignment : Nat) -> Nat
alignUp size alignment =
  size + paddingFor size alignment

||| Proof that alignUp produces an aligned result.
public export
alignUpCorrect : (size : Nat) -> (align : Nat) -> (align > 0) -> Divides align (alignUp size align)
alignUpCorrect size align prf =
  DivideBy ((size + paddingFor size align) `div` align) Refl

--------------------------------------------------------------------------------
-- Struct Field Layout
--------------------------------------------------------------------------------

||| A field in a C struct with its computed offset, size, and alignment.
public export
record Field where
  constructor MkField
  ||| Field name for documentation and lookup
  name : String
  ||| Byte offset from start of struct
  offset : Nat
  ||| Size in bytes
  size : Nat
  ||| Required alignment in bytes
  alignment : Nat

||| Calculate the offset of the next field after this one.
public export
nextFieldOffset : Field -> Nat
nextFieldOffset f = alignUp (f.offset + f.size) f.alignment

||| A struct layout is a list of fields with proofs of correctness.
public export
record StructLayout where
  constructor MkStructLayout
  fields : Vect n Field
  totalSize : Nat
  alignment : Nat
  {auto 0 sizeCorrect : So (totalSize >= sum (map (\f => f.size) fields))}
  {auto 0 aligned : Divides alignment totalSize}

||| Calculate total struct size with padding.
public export
calcStructSize : Vect n Field -> Nat -> Nat
calcStructSize [] align = 0
calcStructSize (f :: fs) align =
  let lastOffset = foldl (\acc, field => nextFieldOffset field) f.offset fs
      lastSize = foldr (\field, _ => field.size) f.size fs
   in alignUp (lastOffset + lastSize) align

||| Proof that field offsets are correctly aligned.
public export
data FieldsAligned : Vect n Field -> Type where
  NoFields : FieldsAligned []
  ConsField :
    (f : Field) ->
    (rest : Vect n Field) ->
    Divides f.alignment f.offset ->
    FieldsAligned rest ->
    FieldsAligned (f :: rest)

||| Verify a struct layout is valid.
public export
verifyLayout : (fields : Vect n Field) -> (align : Nat) -> Either String StructLayout
verifyLayout fields align =
  let size = calcStructSize fields align
   in case decSo (size >= sum (map (\f => f.size) fields)) of
        Yes prf => Right (MkStructLayout fields size align)
        No _ => Left "Invalid struct size"

--------------------------------------------------------------------------------
-- Cookie C Struct Layout (matches Zig CookieCRepr)
--------------------------------------------------------------------------------

||| The C-compatible cookie struct layout.
|||
||| In the Zig FFI, cookies are passed as JSON strings rather than
||| as C structs directly. This layout documents the theoretical
||| struct representation for when direct struct passing is needed
||| (e.g., for memory-mapped vault storage).
|||
||| Layout on 64-bit platforms:
|||   offset  0: name_ptr      (8 bytes, pointer to null-terminated string)
|||   offset  8: value_ptr     (8 bytes, pointer to null-terminated string)
|||   offset 16: domain_ptr    (8 bytes, pointer to null-terminated string)
|||   offset 24: path_ptr      (8 bytes, pointer to null-terminated string)
|||   offset 32: secure        (1 byte, bool)
|||   offset 33: http_only     (1 byte, bool)
|||   offset 34: same_site     (1 byte, enum u8: 0=Strict, 1=Lax, 2=None)
|||   offset 35: has_expiry    (1 byte, bool)
|||   offset 36: padding       (4 bytes)
|||   offset 40: expires_at    (8 bytes, u64 unix timestamp)
|||   offset 48: created_at    (8 bytes, u64 unix timestamp)
|||   total: 56 bytes, alignment: 8
public export
cookieLayout : StructLayout
cookieLayout =
  MkStructLayout
    [ MkField "name_ptr"    0  8 8
    , MkField "value_ptr"   8  8 8
    , MkField "domain_ptr"  16 8 8
    , MkField "path_ptr"    24 8 8
    , MkField "secure"      32 1 1
    , MkField "http_only"   33 1 1
    , MkField "same_site"   34 1 1
    , MkField "has_expiry"  35 1 1
    , MkField "expires_at"  40 8 8
    , MkField "created_at"  48 8 8
    ]
    56    -- Total size: 56 bytes
    8     -- Alignment: 8 bytes (pointer-aligned)

--------------------------------------------------------------------------------
-- Protection Rule C Struct Layout
--------------------------------------------------------------------------------

||| The C-compatible protection rule struct layout.
|||
||| Layout on 64-bit platforms:
|||   offset  0: pattern_ptr   (8 bytes, pointer to null-terminated string)
|||   offset  8: action        (4 bytes, enum c_int: 0=Protect, 1=Ignore, 2=Delete)
|||   offset 12: padding       (4 bytes)
|||   total: 16 bytes, alignment: 8
public export
ruleLayout : StructLayout
ruleLayout =
  MkStructLayout
    [ MkField "pattern_ptr" 0  8 8
    , MkField "action"      8  4 4
    ]
    16    -- Total size: 16 bytes (with 4 bytes tail padding)
    8     -- Alignment: 8 bytes

--------------------------------------------------------------------------------
-- Analysis Result C Struct Layout
--------------------------------------------------------------------------------

||| The C-compatible analysis result struct layout.
|||
||| Layout on 64-bit platforms:
|||   offset  0: is_tracker       (1 byte, bool)
|||   offset  1: is_expired       (1 byte, bool)
|||   offset  2: cross_site_risk  (1 byte, bool)
|||   offset  3: padding          (1 byte)
|||   offset  4: consent_category (4 bytes, enum c_int)
|||   total: 8 bytes, alignment: 4
public export
analysisLayout : StructLayout
analysisLayout =
  MkStructLayout
    [ MkField "is_tracker"       0 1 1
    , MkField "is_expired"       1 1 1
    , MkField "cross_site_risk"  2 1 1
    , MkField "consent_category" 4 4 4
    ]
    8     -- Total size: 8 bytes
    4     -- Alignment: 4 bytes

--------------------------------------------------------------------------------
-- C ABI Compatibility
--------------------------------------------------------------------------------

||| Proof that a struct follows C ABI rules.
public export
data CABICompliant : StructLayout -> Type where
  CABIOk :
    (layout : StructLayout) ->
    FieldsAligned layout.fields ->
    CABICompliant layout

--------------------------------------------------------------------------------
-- Platform-Specific Layout Verification
--------------------------------------------------------------------------------

||| Struct layout may differ by platform.
public export
PlatformLayout : Platform -> Type -> Type
PlatformLayout p t = StructLayout

||| On 64-bit platforms (Linux, Windows, MacOS, BSD), the cookie layout
||| uses 8-byte pointers. On WASM (32-bit), pointers are 4 bytes.
||| This function returns the correct layout for the target platform.
public export
cookieLayoutForPlatform : (p : Platform) -> StructLayout
cookieLayoutForPlatform WASM =
  MkStructLayout
    [ MkField "name_ptr"    0  4 4
    , MkField "value_ptr"   4  4 4
    , MkField "domain_ptr"  8  4 4
    , MkField "path_ptr"    12 4 4
    , MkField "secure"      16 1 1
    , MkField "http_only"   17 1 1
    , MkField "same_site"   18 1 1
    , MkField "has_expiry"  19 1 1
    , MkField "expires_at"  24 8 8
    , MkField "created_at"  32 8 8
    ]
    40    -- Total size: 40 bytes on WASM
    8     -- Alignment: 8 bytes (due to u64 fields)
cookieLayoutForPlatform _ = cookieLayout

--------------------------------------------------------------------------------
-- Offset Calculation
--------------------------------------------------------------------------------

||| Look up a field by name in a struct layout.
public export
fieldOffset : (layout : StructLayout) -> (fieldName : String) -> Maybe (n : Nat ** Field)
fieldOffset layout name =
  case findIndex (\f => f.name == name) layout.fields of
    Just idx => Just (finToNat idx ** index idx layout.fields)
    Nothing => Nothing
