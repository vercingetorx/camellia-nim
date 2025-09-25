import std/[unittest, strutils]
import ../camellia


proc parseHexBytes(line: string): seq[byte] =
  let parts = line.split(":", 1)
  if parts.len < 2:
    raise newException(ValueError, "Expected ':' in line: " & line)
  for token in parts[1].splitWhitespace():
    result.add(byte(parseHexInt(token)))


proc loadCamelliaKats(path: string): seq[tuple[key, pt, ct: seq[byte]]] =
  let lines = readFile(path).splitLines()
  var currentKey: seq[byte]
  var pendingPt: seq[byte]
  for raw in lines:
    let line = raw.strip()
    if line.len == 0 or line.startsWith("Camellia with"):
      continue
    if line.startsWith("K "):
      currentKey = parseHexBytes(raw)
    elif line.startsWith("P "):
      pendingPt = parseHexBytes(raw)
    elif line.startsWith("C "):
      let ct = parseHexBytes(raw)
      if currentKey.len == 0:
        raise newException(ValueError, "Ciphertext before key encountered")
      if pendingPt.len == 0:
        raise newException(ValueError, "Ciphertext before plaintext encountered")
      result.add((currentKey, pendingPt, ct))
      pendingPt.setLen(0)
    # ignore other lines silently
  return result

suite "Camellia known-answer tests":
  test "ECB KATs":
    let kats = loadCamelliaKats("t_camellia.txt")
    check kats.len > 0
    for kat in kats:
      let ctx = newCamelliaEcbCtx(kat.key)
      var enc = newSeq[byte](kat.pt.len)
      ctx.encrypt(kat.pt, enc)
      check enc == kat.ct

      var dec = newSeq[byte](kat.ct.len)
      ctx.decrypt(kat.ct, dec)
      check dec == kat.pt
