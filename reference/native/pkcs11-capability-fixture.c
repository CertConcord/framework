#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* Synthetic ABI fixture only: no token, keys, PIN verification or cryptography. */
typedef unsigned long U;
typedef struct { unsigned char major, minor; } Version;
typedef struct {
  Version cryptokiVersion;
  unsigned char manufacturerID[32];
  U flags;
  unsigned char libraryDescription[32];
  Version libraryVersion;
} Info;
#pragma pack(push, 1)
typedef struct {
  Version cryptokiVersion;
  unsigned char manufacturerID[32];
  U flags;
  unsigned char libraryDescription[32];
  Version libraryVersion;
} PackedInfo;
#pragma pack(pop)
typedef struct { U min, max, flags; } MechanismInfo;
static U mode, used, trace[128];
static void mark(U event) { if (used < 128) trace[used++] = event; }
void fixture_configure(U selected) { mode = selected; used = 0; memset(trace, 0, sizeof(trace)); }
void fixture_mode(U selected) { mode = selected; }
U fixture_count(void) { return used; }
U fixture_event(U i) { return i < used ? trace[i] : 0; }
U fixture_info_size(void) { return sizeof(Info); }
U fixture_packed_info_size(void) { return sizeof(PackedInfo); }
U C_Initialize(void *args) {
  mark(1);
  if (mode == 31) return 5;
  return mode == 12 || mode == 28 || mode == 29 || mode == 30 ? 0x191 : 0;
}
U C_Finalize(void *args) { mark(8); return 0; }
U C_GetInfo(void *output) {
  Info info;
  mark(2);
  if (mode == 5 || mode == 30) return 5;
  memset(&info, 0, sizeof(info));
  info.cryptokiVersion.major = (mode == 1 || mode == 6 || mode == 26) ? 2 : mode == 8 ? 4 : 3;
  info.cryptokiVersion.minor = (mode == 1 || mode == 6) ? 40 :
    mode == 2 || mode == 24 ? 1 : mode == 8 || mode == 23 ? 0 : mode == 25 ? 3 : mode == 26 ? 20 : 2;
  memset(info.manufacturerID, ' ', 32); memcpy(info.manufacturerID, "Synthetic fixture", 17);
  memset(info.libraryDescription, ' ', 32); memcpy(info.libraryDescription, "No token or cryptography", 24);
  info.libraryVersion.major = 1;
  if (mode == 39) {
    PackedInfo packed;
    memset(&packed, 0, sizeof(packed));
    packed.cryptokiVersion = info.cryptokiVersion;
    memset(packed.manufacturerID, 'P', sizeof(packed.manufacturerID));
    packed.flags = 0x11223344;
    memcpy(output, &packed, sizeof(packed));
  } else memcpy(output, &info, sizeof(info));
  return 0;
}
U C_GetMechanismList(U slot, U *list, U *count) {
  const U all[] = {0x1040, 0x1041, 0x1c, 0x1d};
  U length = (mode == 1 || mode == 3 || mode == 6 || mode == 12) ? 2 : mode == 33 ? 3 : 4;
  mark(3);
  if (mode == 32) return 5;
  if (mode == 9) { *count = 65536; return 0; }
  if (mode == 16) { *count = 0; return 0; }
  if (!list) { *count = length; return 0; }
  if (mode == 10) { *count = length + 1; return 0x150; }
  if (*count < length) { *count = length; return 0x150; }
  memcpy(list, all, length * sizeof(U));
  if (mode == 33) list[2] = 0x1d;
  if (mode == 15) list[3] = list[2];
  *count = mode == 17 ? length + 1 : length;
  return 0;
}
U C_GetMechanismInfo(U slot, U mechanism, MechanismInfo *info) {
  const int ec = mechanism == 0x1040 || mechanism == 0x1041;
  const int sign = mechanism == 0x1041 || mechanism == 0x1d;
  mark(4);
  if (mode == 11 || mode == 37) return 0x70;
  info->min = ec ? 256 : 1312;
  info->max = ec ? 521 : 2592;
  info->flags = sign ? 0x800 : 0x10000;
  if (mode == 4 && mechanism == 0x1d) info->flags = 0;
  if (mode == 18 && ec) info->min = 257;
  if (mode == 19 && !ec) info->min = 2700;
  if (mode == 20 && !ec) info->max = 2000;
  if (mode == 21 && !ec) info->min = 2000;
  if (mode == 22 && sign) info->flags = 0x10000;
  if (mode == 34 && !sign) info->flags = 0x800;
  if (mode == 35 && !sign) info->min = 65536;
  if (mode == 36 && sign) info->flags = 0;
  if (mode == 38) info->min = info->max = 0;
  return 0;
}
U C_OpenSession(U slot, U flags, void *app, void *notify, U *session) { mark(5); if (mode == 14 || mode == 29) return 5; *session = 47; return 0; }
U C_CloseSession(U session) { mark(7); return 0; }
U C_Login(U session, U user, unsigned char *pin, U length) { mark(6); return mode == 13 || mode == 28 ? 0xa0 : 0; }
U C_Logout(U session) { mark(16); return 0; }
U C_FindObjectsInit(U session, void *attrs, U count) { mark(9); return 0x54; }
U C_FindObjects(U session, U *objects, U count, U *found) { mark(10); return 0x54; }
U C_FindObjectsFinal(U session) { mark(11); return 0x54; }
U C_GetAttributeValue(U session, U object, void *attrs, U count) { mark(12); return 0x54; }
U C_SignInit(U session, void *mechanism, U key) { mark(13); return 0x54; }
U C_Sign(U session, unsigned char *input, U length, unsigned char *signature, U *size) { mark(14); return 0x54; }
U C_GenerateKeyPair(U session, void *mechanism, void *pub, U pubCount, void *priv, U privCount, U *pk, U *sk) { mark(15); return 0x54; }
