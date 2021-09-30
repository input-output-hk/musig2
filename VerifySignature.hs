#!/usr/bin/env cabal

{- cabal:
build-depends: base
             , bytestring
             , cardano-crypto
             , cryptonite
-}

import Crypto.ECC.Ed25519Donna (PublicKey, publicKey, signature, verify)
import Crypto.Error (throwCryptoErrorIO)
import qualified Data.ByteString as BS

main :: IO ()
main = do
  pubKey <- throwCryptoErrorIO . publicKey =<< BS.readFile "aggregate.pub"
  verifySignature pubKey "valid.signed"

verifySignature :: PublicKey -> String -> IO ()
verifySignature pubKey fn = do
  sm <- BS.readFile fn
  let (sig, msg) = BS.splitAt 64 sm
  sig' <- throwCryptoErrorIO $ signature sig
  let result =
        if verify pubKey msg sig'
          then "✓ Valid"
          else "✘ Invalid"
  putStrLn $ fn <> " " <> show msg <> " " <> result
