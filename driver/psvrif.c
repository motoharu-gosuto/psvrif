#include <psp2kern/types.h>
#include <psp2kern/kernel/modulemgr.h>
#include <psp2kern/kernel/sysmem.h>
#include <psp2kern/kernel/threadmgr.h>
#include <psp2kern/io/fcntl.h>
#include <psp2kern/net/net.h>

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include <taihen.h>
#include <module.h>

//----

#define SceSblSsMgrForDriver_NID 0x61E9428D
#define SceSblAuthMgrForDriver_NID 0x4EB2B1BB
#define SceNpDrmForDriver_NID 0xD84DC44A
#define SceRtcForDriver_NID 0x351D827

typedef SceUInt64 SceRtcTick;

#pragma pack(push,1)

typedef struct rif_info //size is 0x70
{
   char content_id[0x30];
   int version_number;
   int rif_lic_flags;
   int lic_type0; //lic type related
   int lic_type1; //lic type related
   char account_id[0x08];
   char rif_data_98[0x08];
   SceRtcTick lic_start_time;
   SceRtcTick lic_exp_time;
   char dec_rif_key[0x10]; //decrypted rif key
}rif_info;

typedef struct dec_buffer
{
   char rif_key[0x10];      //0x00
   char unk0[0x30];         //0x10
   char primary_keys[0x20]; //0x40
   char rif_data[0x70];     //0x60
   char unk1[0x30];         //0xD0
}dec_buffer;

#pragma pack(pop)

int ksceRegMgrGetKeyStr(char* category, char* name, char* buf, int size);
int ksceRegMgrGetKeyBin(char* category, char* name, char* buf, int size);

typedef int (sceSblSsMgrGetConsoleIdForDriver_t)(char* cid);
typedef int (sceKernelGetOpenPsIdForDriver_t)(char* psid);
typedef int (sceSblAuthMgrGetEKcForDriver_t)(char* data, int size, int key_id);
typedef int (aes_encrypt_1D3AAEC_t)(char *data,	int size, const	char* key, char** end);
typedef int (aes_decrypt_1D3AAF4_t)(char *data, int size,	const char* key, char** end);
typedef int (sceNpDrmGetFixedRifNameForDriver_t)(char* name, int ignored, int unk1, int unk2);
typedef int (sceNpDrmGetRifInfoForDriver_t)(const char* rif_data, int rif_size, int num, char* content_id, char* account_id, int* version_number, int* rif_lic_flags, int* lic_type0, int* lic_type1, SceRtcTick* lic_start_time, SceRtcTick* lic_exp_time, char* rif_data_98);
typedef int (sceRtcFormatRFC3339ForDriver_t)(char* pszDateTime, const SceRtcTick* utc, int iTimeZoneMinutes);
typedef int (sceNpDrmGetRifVitaKeyForDriver_t)(const char* rif_data, char* dec_rif_key, int* lic_type0, int* lic_type1, SceRtcTick* lic_start_time, SceRtcTick* lic_exp_time, int* rif_lic_flags);
typedef int (sceSblAuthMgrDecBindDataForDriver_t)(char* rif_key, int size0, const char* primary_keys, int size1, int zero);

sceSblSsMgrGetConsoleIdForDriver_t* sceSblSsMgrGetConsoleIdForDriver;
sceKernelGetOpenPsIdForDriver_t* sceKernelGetOpenPsIdForDriver;
sceSblAuthMgrGetEKcForDriver_t* sceSblAuthMgrGetEKcForDriver;
aes_encrypt_1D3AAEC_t* aes_encrypt_1D3AAEC;
aes_decrypt_1D3AAF4_t* aes_decrypt_1D3AAF4;
sceNpDrmGetFixedRifNameForDriver_t* sceNpDrmGetFixedRifNameForDriver;
sceNpDrmGetRifInfoForDriver_t* sceNpDrmGetRifInfoForDriver;
sceRtcFormatRFC3339ForDriver_t* sceRtcFormatRFC3339ForDriver;
sceNpDrmGetRifVitaKeyForDriver_t* sceNpDrmGetRifVitaKeyForDriver;
sceSblAuthMgrDecBindDataForDriver_t* sceSblAuthMgrDecBindDataForDriver;

//---------

char sprintfBuffer[256];

void FILE_GLOBAL_WRITE_LEN(char* msg)
{
  SceUID global_log_fd = ksceIoOpen("ux0:dump/rif_log.txt", SCE_O_CREAT | SCE_O_APPEND | SCE_O_WRONLY, 0777);

  if(global_log_fd >= 0)
  {
    ksceIoWrite(global_log_fd, msg, strlen(msg));
    ksceIoClose(global_log_fd);
  }  
}

int initialize_functions()
{
  int res = module_get_export_func(KERNEL_PID, "SceSblSsMgr", SceSblSsMgrForDriver_NID, 0xfc6cdd68, (uintptr_t*)&sceSblSsMgrGetConsoleIdForDriver);
  if(res < 0)
  {
    snprintf(sprintfBuffer, 256, "failed to set sceSblSsMgrGetConsoleIdForDriver : %x\n", res);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
    return -1;
  }

  FILE_GLOBAL_WRITE_LEN("set sceSblSsMgrGetConsoleIdForDriver\n");

  res = module_get_export_func(KERNEL_PID, "SceSblSsMgr", SceSblSsMgrForDriver_NID, 0xa5b5d269, (uintptr_t*)&sceKernelGetOpenPsIdForDriver);
  if(res < 0)
  {
    snprintf(sprintfBuffer, 256, "failed to set sceKernelGetOpenPsIdForDriver : %x\n", res);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
    return -1;
  }

  FILE_GLOBAL_WRITE_LEN("set sceKernelGetOpenPsIdForDriver\n");

  res = module_get_export_func(KERNEL_PID, "SceSblAuthMgr", SceSblAuthMgrForDriver_NID, 0x868b9e9a, (uintptr_t*)&sceSblAuthMgrGetEKcForDriver);
  if(res < 0)
  {
    snprintf(sprintfBuffer, 256, "failed to set sceSblAuthMgrGetEKcForDriver : %x\n", res);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
    return -1;
  }

  FILE_GLOBAL_WRITE_LEN("set sceSblAuthMgrGetEKcForDriver\n");

  res = module_get_export_func(KERNEL_PID, "SceSblAuthMgr", SceSblAuthMgrForDriver_NID, 0x41daea12, (uintptr_t*)&sceSblAuthMgrDecBindDataForDriver);
  if(res < 0)
  {
    snprintf(sprintfBuffer, 256, "failed to set sceSblAuthMgrDecBindDataForDriver : %x\n", res);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
    return -1;
  }

  FILE_GLOBAL_WRITE_LEN("set sceSblAuthMgrDecBindDataForDriver\n");

  tai_module_info_t npdrm_info;
  npdrm_info.size = sizeof(tai_module_info_t);
  int modres = taiGetModuleInfoForKernel(KERNEL_PID, "SceNpDrm", &npdrm_info);
  if (modres >= 0)
  {
    int ofstRes = module_get_offset(KERNEL_PID, npdrm_info.modid, 0, 0x1D3AAEC - 0x1D30000 + 1, (uintptr_t*)&aes_encrypt_1D3AAEC);
    if(ofstRes < 0)
    {
      snprintf(sprintfBuffer, 256, "failed to set aes_encrypt_1D3AAEC : %x\n", ofstRes);
      FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
      return -1;
    }

    FILE_GLOBAL_WRITE_LEN("set aes_encrypt_1D3AAEC\n");

    ofstRes = module_get_offset(KERNEL_PID, npdrm_info.modid, 0, 0x1D3AAF4 - 0x1D30000 + 1, (uintptr_t*)&aes_decrypt_1D3AAF4);
    if(ofstRes < 0)
    {
      snprintf(sprintfBuffer, 256, "failed to set aes_decrypt_1D3AAF4 : %x\n", ofstRes);
      FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
      return -1;
    }

    FILE_GLOBAL_WRITE_LEN("set aes_decrypt_1D3AAF4\n");
  }
  else
  {
    snprintf(sprintfBuffer, 256, "failed to get SceNpDrm module info : %x\n", modres);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
    return -1;
  }

  res = module_get_export_func(KERNEL_PID, "SceNpDrm", SceNpDrmForDriver_NID, 0x5d73448c, (uintptr_t*)&sceNpDrmGetFixedRifNameForDriver);
  if(res < 0)
  {
    snprintf(sprintfBuffer, 256, "failed to set sceNpDrmGetFixedRifNameForDriver : %x\n", res);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
    return -1;
  }

  FILE_GLOBAL_WRITE_LEN("set sceNpDrmGetFixedRifNameForDriver\n");

  res = module_get_export_func(KERNEL_PID, "SceNpDrm", SceNpDrmForDriver_NID, 0xdb406eae, (uintptr_t*)&sceNpDrmGetRifInfoForDriver);
  if(res < 0)
  {
    snprintf(sprintfBuffer, 256, "failed to set sceNpDrmGetRifInfoForDriver : %x\n", res);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
    return -1;
  }

  FILE_GLOBAL_WRITE_LEN("set sceNpDrmGetRifInfoForDriver\n");

  res = module_get_export_func(KERNEL_PID, "SceNpDrm", SceNpDrmForDriver_NID, 0x723322b5, (uintptr_t*)&sceNpDrmGetRifVitaKeyForDriver);
  if(res < 0)
  {
    snprintf(sprintfBuffer, 256, "failed to set sceNpDrmGetRifVitaKeyForDriver : %x\n", res);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
    return -1;
  }

  FILE_GLOBAL_WRITE_LEN("set sceNpDrmGetRifVitaKeyForDriver\n");
  
  res = module_get_export_func(KERNEL_PID, "SceRtc", SceRtcForDriver_NID, 0xd32ac698, (uintptr_t*)&sceRtcFormatRFC3339ForDriver);
  if(res < 0)
  {
    snprintf(sprintfBuffer, 256, "failed to set sceRtcFormatRFC3339ForDriver : %x\n", res);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
    return -1;
  }

  FILE_GLOBAL_WRITE_LEN("set sceRtcFormatRFC3339ForDriver\n");  

  return 0;
}

int print_bytes(const char* data, int len)
{
  for(int i = 0; i < len; i++)
  {
    snprintf(sprintfBuffer, 256, "%02x", data[i]);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
  }

  FILE_GLOBAL_WRITE_LEN("\n");

  return 0;
}

char reg_buffer[2048];

int get_accont_id(char* account_id)
{
  memset(reg_buffer, 0, sizeof(reg_buffer));

  int reg_res = ksceRegMgrGetKeyBin("/CONFIG/NP/", "account_id", reg_buffer, sizeof(reg_buffer));
  if(reg_res < 0)
  {
    snprintf(sprintfBuffer, 256, "failed to get account_id: %x\n", reg_res);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
    return -1;
  }

  FILE_GLOBAL_WRITE_LEN("got psn id\n");

  memcpy(account_id, reg_buffer, 0x10);

  print_bytes(account_id, 0x10);

  return 0;
}

int read_id_dat(char* buffer)
{
  memset(buffer, 0, 0x200);

  SceUID fd = ksceIoOpen("ux0:id.dat", SCE_O_RDONLY, 0777);
  if(fd < 0)
  {
    snprintf(sprintfBuffer, 256, "failed to open id.dat: %x\n", fd);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
    return -1;
  }

  SceOff filesize = ksceIoLseek(fd, 0, SCE_SEEK_END);
  if(filesize < 0)
  {
    ksceIoClose(fd);

    snprintf(sprintfBuffer, 256, "failed to seek id.dat: %x\n", filesize);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
    return -1;
  }

  SceOff sres = ksceIoLseek(fd, 0, SCE_SEEK_SET);
  if(sres < 0)
  {
    ksceIoClose(fd);

    snprintf(sprintfBuffer, 256, "failed to seek id.dat: %x\n", sres);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
    return -1;
  }

  int rb = ksceIoRead(fd, buffer, filesize);
  if(rb != filesize)
  {
    ksceIoClose(fd);

    snprintf(sprintfBuffer, 256, "failed to read id.dat: %x\n", rb);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
    return -1;
  }

  int res = ksceIoClose(fd);
  if(res < 0)
  {
    snprintf(sprintfBuffer, 256, "failed to close id.dat: %x\n", res);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
    return -1;
  }

  FILE_GLOBAL_WRITE_LEN("read id.dat\n");

  return 0;
}

int read_act_dat(char* buffer)
{
  memset(buffer, 0, 0x1040);

  SceUID fd = ksceIoOpen("tm0:npdrm/act.dat", SCE_O_RDONLY, 0777);
  if(fd < 0)
  {
    snprintf(sprintfBuffer, 256, "failed to open act.dat: %x\n", fd);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
    return -1;
  }

  int rb = ksceIoRead(fd, buffer, 0x1038);
  if(rb != 0x1038)
  {
    ksceIoClose(fd);

    snprintf(sprintfBuffer, 256, "failed to read act.dat: %x\n", rb);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
    return -1;
  }

  int res = ksceIoClose(fd);
  if(res < 0)
  {
    snprintf(sprintfBuffer, 256, "failed to close act.dat: %x\n", res);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
    return -1;
  }

  FILE_GLOBAL_WRITE_LEN("read act.dat\n");

  return 0;
}

int check_psn_id(const char* act, const char* acc)
{
  if(memcmp(act + 8, acc, 8) != 0)
  {
    FILE_GLOBAL_WRITE_LEN("invalid psn account id\n");
    return -1;
  }

  FILE_GLOBAL_WRITE_LEN("valid psn account id\n");

  return 0;
}

int get_cid(char* cid)
{
  memset(cid, 0, 0x10);

  int res = sceSblSsMgrGetConsoleIdForDriver(cid);
  if(res < 0)
  {
    snprintf(sprintfBuffer, 256, "failed to get cid: %x\n", res);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
    return -1;
  }

  FILE_GLOBAL_WRITE_LEN("got cid\n");

  print_bytes(cid, 0x10);

  return 0;
}

int get_psid(char* psid)
{
  memset(psid, 0, 0x10);

  int res = sceKernelGetOpenPsIdForDriver(psid);
  if(res < 0)
  {
    snprintf(sprintfBuffer, 256, "failed to get psid: %x\n", res);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
    return -1;
  }

  FILE_GLOBAL_WRITE_LEN("got psid\n");

  print_bytes(psid, 0x10);

  return 0;
}

int verify_psid(const char* act, const char* psid)
{
  if(memcmp(act + 0x850, psid, 0x10) != 0)
  {
    FILE_GLOBAL_WRITE_LEN("invalid psid\n");
    return -1;
  }

  FILE_GLOBAL_WRITE_LEN("valid psid\n");

  return 0;
}

int dec_static_keys(const char* src, char* dst)
{
  memcpy(dst, src, 0xC0);

  int res = sceSblAuthMgrGetEKcForDriver(dst, 0xC0, 0);
  if(res < 0)
  {
    snprintf(sprintfBuffer, 256, "failed to decrypt static keys: %x\n", res);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
    return -1;
  }

  FILE_GLOBAL_WRITE_LEN("decrypted static keys\n");

  return 0;
}

int re_enc_static_keys(char* data, const char* cid)
{
  int res = aes_encrypt_1D3AAEC(data, 0x10, cid, 0);
  if(res < 0)
  {
    snprintf(sprintfBuffer, 256, "failed to re encrypt static keys: %x\n", res);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
    return -1;
  }

  FILE_GLOBAL_WRITE_LEN("re encrypted static keys\n");

  return 0;
}

int dec_primary_key_table(char* act, const char* keys)
{
  int res = aes_decrypt_1D3AAF4(act + 0x10, 0x800, keys, 0);
  if(res < 0)
  {
    snprintf(sprintfBuffer, 256, "failed to decrypt primary key table: %x\n", res);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
    return -1;
  }

  FILE_GLOBAL_WRITE_LEN("decrypted primary key table\n");

  return 0;
}

int get_fixed_rif_path(char* rif_path, const char* title)
{
  char name[0x30];
  memset(name, 0, sizeof(name));

  int res = sceNpDrmGetFixedRifNameForDriver(name, sizeof(name), 0, 0);
  if(res < 0)
  {
    snprintf(sprintfBuffer, 256, "failed to get fixed rif name: %x\n", res);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
    return -1;
  }

  snprintf(sprintfBuffer, 256, "got fixed rif name: %s\n", name);
  FILE_GLOBAL_WRITE_LEN(sprintfBuffer);

  memset(rif_path, 0, 0x80);

  snprintf(rif_path, 0x80, "ux0:license/app/%s/%s", title, name);

  return 0;
}

int get_rif_data(const char* rif_path, char* rifd)
{
  memset(rifd, 0, 0x200);

  SceUID fd = ksceIoOpen(rif_path, SCE_O_RDONLY, 0777);
  if(fd < 0)
  {
    snprintf(sprintfBuffer, 256, "failed to open rif: %x\n", fd);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
    return -1;
  }

  int rb = ksceIoRead(fd, rifd, 0x200);
  if(rb != 0x200)
  {
    ksceIoClose(fd);

    snprintf(sprintfBuffer, 256, "failed to read rif: %x\n", rb);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
    return -1;
  }

  int res = ksceIoClose(fd);
  if(res < 0)
  {
    snprintf(sprintfBuffer, 256, "failed to close rif: %x\n", res);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
    return -1;
  }

  FILE_GLOBAL_WRITE_LEN("read rif\n");

  return 0;
}

int print_rif_data(const char* dec_rif_key, int lic_type0, int lic_type1, const SceRtcTick* lic_start_time, const SceRtcTick* lic_exp_time, int rif_lic_flags)
{
  snprintf(sprintfBuffer, 256, "rif lic flags: %x\n", rif_lic_flags);
  FILE_GLOBAL_WRITE_LEN(sprintfBuffer);

  snprintf(sprintfBuffer, 256, "lic type0: %x\n", lic_type0);
  FILE_GLOBAL_WRITE_LEN(sprintfBuffer);

  snprintf(sprintfBuffer, 256, "lic type1: %x\n", lic_type1);
  FILE_GLOBAL_WRITE_LEN(sprintfBuffer);

  //   

  char lic_start_time_str[0x20];
  memset(lic_start_time_str, 0, 0x20);
  int res = sceRtcFormatRFC3339ForDriver(lic_start_time_str, lic_start_time, 0x21C);
  if(res < 0)
  {
    snprintf(sprintfBuffer, 256, "lic start time: %s\n", "NONE");
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
  }
  else
  {
    snprintf(sprintfBuffer, 256, "lic start time: %s\n", lic_start_time_str);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
  }

  //
  
  char lic_exp_time_str[0x20];
  memset(lic_exp_time_str, 0, 0x20);
  res = sceRtcFormatRFC3339ForDriver(lic_exp_time_str,lic_exp_time, 0x21C);
  if(res < 0)
  {
    snprintf(sprintfBuffer, 256, "lic start exp time: %s\n", "NONE");
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
  }
  else
  {
    snprintf(sprintfBuffer, 256, "lic start exp time: %s\n", lic_exp_time_str);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
  }

  //
  
  FILE_GLOBAL_WRITE_LEN("rif dec key:\n");

  print_bytes(dec_rif_key, 0x10);

  return 0;
}

int get_dec_rif_key(const char* rifd, char* klicensee)
{
  rif_info info;

  memset(&info, 0, sizeof(rif_info));

  int res = sceNpDrmGetRifInfoForDriver(rifd, 0x200, 1, info.content_id, info.account_id, &info.version_number, &info.rif_lic_flags, &info.lic_type0, &info.lic_type1, &info.lic_start_time, &info.lic_exp_time, info.rif_data_98);
  if(res < 0)
  {
    snprintf(sprintfBuffer, 256, "failed to get rif info: %x\n", res);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
    return -1;
  }

  res = sceNpDrmGetRifVitaKeyForDriver(rifd, info.dec_rif_key, &info.lic_type0, &info.lic_type1, &info.lic_start_time, &info.lic_exp_time, &info.rif_lic_flags);
  if(res < 0)
  {
    snprintf(sprintfBuffer, 256, "failed to get rif dec key: %x\n", res);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
    return -1;
  }
  
  //

  FILE_GLOBAL_WRITE_LEN("content id:\n");

  snprintf(sprintfBuffer, 256, "%s\n", info.content_id);
  FILE_GLOBAL_WRITE_LEN(sprintfBuffer);

  //
  
  FILE_GLOBAL_WRITE_LEN("account id:\n");

  print_bytes(info.account_id, 0x08);

  //
  
  FILE_GLOBAL_WRITE_LEN("rif data 98:\n");

  print_bytes(info.rif_data_98, 0x08);

  //

  snprintf(sprintfBuffer, 256, "version number: %x\n", info.version_number);
  FILE_GLOBAL_WRITE_LEN(sprintfBuffer);

  print_rif_data(info.dec_rif_key, info.lic_type0, info.lic_type1, &info.lic_start_time, &info.lic_exp_time, info.rif_lic_flags);

  memcpy(klicensee, info.dec_rif_key, 0x10);

  return 0;
}

int get_cmd56_handshake(char* data)
{
  memset(data, 0, 0x20);
  return 0;
}

int dec_rif_key_aes(const char* rifd, const char* keys, char* klicensee)
{
  memset(klicensee, 0, 0x10);

  char primary_table_key[0x10];

  memcpy(primary_table_key, rifd + 0x40, 0x10);
  
  int res = aes_decrypt_1D3AAF4(primary_table_key, 0x10, keys + 0x10, 0); //decrypt index with static key 2
  if(res < 0)
  {
    snprintf(sprintfBuffer, 256, "failed to decrypt primary key table index: %x\n", res);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
    return -1;
  }

  FILE_GLOBAL_WRITE_LEN("decrypted primary key table index\n");

  int index = primary_table_key[15] & 0x7F;
  
  char rif_key[0x10];

  memcpy(rif_key, rifd + 0x50, 0x10);

  res = aes_decrypt_1D3AAF4(rif_key, 0x10, keys + index * 0x10, 0); //decrypt rif key with primary key
  if(res < 0)
  {
    snprintf(sprintfBuffer, 256, "failed to decrypt primary key table index: %x\n", res);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
    return -1;
  }

  memcpy(klicensee, rif_key, 0x10);

  FILE_GLOBAL_WRITE_LEN("klicensee:\n");

  print_bytes(klicensee, 0x10);

  return 0;
}

int dec_rif_key_bind(dec_buffer* decbuf, char* klicensee)
{
  int res = sceSblAuthMgrDecBindDataForDriver(decbuf->rif_key, 0x10, decbuf->primary_keys, 0x90, 0);

  if(res < 0)
    memset(klicensee, 0, 0x10);
  else
    memcpy(klicensee, decbuf->rif_key, 0x10);

  if(res < 0)
  {
    snprintf(sprintfBuffer, 256, "failed to decrypt klicensee: %x\n", res);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
    return -1;
  }

  FILE_GLOBAL_WRITE_LEN("klicensee:\n");

  print_bytes(klicensee, 0x10);

  return 0;
}

//buffer MUST BE aligned or sceSblAuthMgrDecBindDataForDriver will throw an error
dec_buffer decbuf_inst __attribute__ ((aligned(128)));

//still need to figure out flags
int get_rif_key_1D37B48_part(const char* act_data, const char* static_keys, const char* rif_data, const char* cmd56_handshake, int lic_flag, int lic_derived_flag, int onfly_bit11, int enc_select, char* klicensee)
{   
  if(enc_select == 1)
  {
    return dec_rif_key_aes(rif_data, static_keys, klicensee);
  }
  else
  {
    dec_buffer* decbufptr = &decbuf_inst;

    memset(decbufptr, 0, 0x100);

    memcpy(decbufptr->rif_data, rif_data, 0x70);

    if(onfly_bit11 == 0)
    {
      if(lic_flag == 0xD)
      {
        memcpy(decbufptr->primary_keys, static_keys + 0x20, 0x20); //keys 3 and 4

        memcpy(decbufptr->rif_key, rif_data + 0xA0, 0x10);

        return dec_rif_key_bind(decbufptr, klicensee);
      }
      else
      {
        memcpy(decbufptr->primary_keys, act_data + 0x10, 0x20); //primary keys 1 and 2

        memcpy(decbufptr->rif_key, rif_data + 0xA0, 0x10);

        return dec_rif_key_bind(decbufptr, klicensee);
      }
    }
    else
    {
      if(lic_derived_flag == 0)
      {
        memcpy(decbufptr->primary_keys, cmd56_handshake, 0x20);

        memcpy(decbufptr->rif_key, rif_data + 0xA0, 0x10);

        return dec_rif_key_bind(decbufptr, klicensee);
      }
      else
      { 
        memcpy(decbufptr->primary_keys, cmd56_handshake, 0x20);

        memcpy(decbufptr->rif_key, decbufptr->rif_data + 0x50, 0x10); //rif key

        memset(decbufptr->rif_data + 0x50, 0, 0x10); //clear rif key
        
        return dec_rif_key_bind(decbufptr, klicensee);
      }
    }
  }
}

char* get_static_keys_ptr()
{
  uintptr_t addr = 0;

  tai_module_info_t npdrm_info;
  npdrm_info.size = sizeof(tai_module_info_t);
  int modres = taiGetModuleInfoForKernel(KERNEL_PID, "SceNpDrm", &npdrm_info);
  if (modres >= 0)
  {
    module_get_offset(KERNEL_PID, npdrm_info.modid, 0, 0x1D411D0 - 0x1D30000, (uintptr_t*)&addr);
  }

  return (char*)addr;
}

char act_dat_data[0x1040];
char id_dat_data[0x200];
char account_id[0x10];
char cid[0x10];
char psid[0x10];
char dec_static_keys_table[0xC0];
char rif_path[0x80];
char rif_data[0x200];
char cmd56_handshake[0x20];
char klicensee_api[0x10];
char klicensee_custom[0x10];

int decrypt()
{
  if(initialize_functions() < 0)
    return -1;

  if(read_act_dat(act_dat_data) < 0)
    return -1;

  if(read_id_dat(id_dat_data) < 0)
    return -1;

  if(get_accont_id(account_id) < 0)
    return -1;

  if(check_psn_id(act_dat_data, account_id) < 0)
    return -1;

  if(get_cid(cid) < 0)
    return -1;

  if(get_psid(psid) < 0)
    return -1;

  if(dec_static_keys(get_static_keys_ptr(), dec_static_keys_table) < 0)
    return -1;

  if(re_enc_static_keys(dec_static_keys_table, cid) < 0)
    return -1;

  if(verify_psid(act_dat_data, psid) < 0)
    return -1;

  if(dec_primary_key_table(act_dat_data, dec_static_keys_table) < 0)
    return -1;

  if(get_fixed_rif_path(rif_path, "PCSC00082") < 0)
    return -1;

  if(get_rif_data(rif_path, rif_data) < 0)
    return -1;

  FILE_GLOBAL_WRITE_LEN("use npdrm API to get klicensee\n");

  if(get_dec_rif_key(rif_data, klicensee_api) < 0)
    return -1;

  FILE_GLOBAL_WRITE_LEN("use custom code to get klicensee\n");

  if(get_cmd56_handshake(cmd56_handshake) < 0)
    return -1;

  //there are 5 scenarios for decryption. still need to figure out flags
  if(get_rif_key_1D37B48_part(act_dat_data, dec_static_keys_table, rif_data, cmd56_handshake, 0xD, 0, 0, 0, klicensee_custom) < 0)
    return -1;

  if(memcmp(klicensee_api, klicensee_custom, 0x10) != 0)
  {
    FILE_GLOBAL_WRITE_LEN("ERROR: keys are not equal\n");
  }
  else
  {
    FILE_GLOBAL_WRITE_LEN("SUCCESS: keys are equal\n");
  }
  
  return 0;
}

tai_hook_ref_t npdrm_723322b5_hook_ref;
SceUID npdrm_723322b5_hook_id = -1;

tai_hook_ref_t npdrm_41daea12_hook_ref;
SceUID npdrm_41daea12_hook_id = -1;

//sceNpDrmGetRifVitaKeyForDriver
int npdrm_723322b5_hook(char* rif_data, char* dec_rif_key, int* lic_type0, int* lic_type1, SceRtcTick* lic_start_time, SceRtcTick* lic_exp_time, int* rif_lic_flags)
{
  int res = TAI_CONTINUE(int, npdrm_723322b5_hook_ref, rif_data, dec_rif_key, lic_type0, lic_type1, lic_start_time, lic_exp_time, rif_lic_flags);

  FILE_GLOBAL_WRITE_LEN("--- sceNpDrmGetRifVitaKeyForDriver ---\n");
  print_rif_data(dec_rif_key, *lic_type0, *lic_type1, lic_start_time, lic_exp_time, *rif_lic_flags);

  return res;
}

int print_possible_keys()
{
  tai_module_info_t npdrm_info;
  npdrm_info.size = sizeof(tai_module_info_t);
  int modres = taiGetModuleInfoForKernel(KERNEL_PID, "SceNpDrm", &npdrm_info);
  if (modres >= 0)
  {
    uintptr_t ofst = 0;
    int ofstRes = module_get_offset(KERNEL_PID, npdrm_info.modid, 1, 0x30, &ofst);
    if(ofstRes < 0)
    {
      snprintf(sprintfBuffer, 256, "failed to get npdrm offset : %x\n", ofstRes);
      FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
      return -1;
    }

    FILE_GLOBAL_WRITE_LEN("static keys:\n");
    print_bytes((char*)ofst, 0x20);

    //---

    ofst = 0;
    ofstRes = module_get_offset(KERNEL_PID, npdrm_info.modid, 1, 0xE10, &ofst);
    if(ofstRes < 0)
    {
      snprintf(sprintfBuffer, 256, "failed to get npdrm offset : %x\n", ofstRes);
      FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
      return -1;
    }

    FILE_GLOBAL_WRITE_LEN("primary keys:\n");
    print_bytes((char*)ofst, 0x20);
  }

  return 0;
}

//sceSblAuthMgrDecBindDataForDriver
int npdrm_41daea12_hook(char* rif_key, int size0, char* primary_keys, int size1, int zero)
{
  FILE_GLOBAL_WRITE_LEN("--- sceSblAuthMgrDecBindDataForDriver ---\n");

  FILE_GLOBAL_WRITE_LEN("rif key enc:\n");
  print_bytes(rif_key, size0);

  int res = TAI_CONTINUE(int, npdrm_41daea12_hook_ref, rif_key, size0, primary_keys, size1, zero);

  snprintf(sprintfBuffer, 256, "arg_0 : %x\n", zero);
  FILE_GLOBAL_WRITE_LEN(sprintfBuffer);

  FILE_GLOBAL_WRITE_LEN("primary keys:\n");
  print_bytes(primary_keys, size1);

  FILE_GLOBAL_WRITE_LEN("rif key dec:\n");
  print_bytes(rif_key, size0);

  print_possible_keys();

  return res;
}

int initialize_hooks()
{
  tai_module_info_t npdrm_info;
  npdrm_info.size = sizeof(tai_module_info_t);
  int modres = taiGetModuleInfoForKernel(KERNEL_PID, "SceNpDrm", &npdrm_info);
  if (modres >= 0)
  {
    //can not hook export because of henkaku
    //npdrm_723322b5_hook_id = taiHookFunctionImportForKernel(KERNEL_PID, &npdrm_723322b5_hook_ref, "SceAppMgr", SceNpDrmForDriver_NID, 0x723322b5, npdrm_723322b5_hook);

    //npdrm_41daea12_hook_id = taiHookFunctionImportForKernel(KERNEL_PID, &npdrm_41daea12_hook_ref, "SceNpDrm", SceSblAuthMgrForDriver_NID, 0x41daea12, npdrm_41daea12_hook);

    //hook export to test calls outside of npdrm
    //npdrm_41daea12_hook_id = taiHookFunctionExportForKernel(KERNEL_PID, &npdrm_41daea12_hook_ref, "SceSblAuthMgr", SceSblAuthMgrForDriver_NID, 0x41daea12, npdrm_41daea12_hook);
  }

  if(npdrm_723322b5_hook_id < 0)
  {
    snprintf(sprintfBuffer, 256, "failed to set npdrm_723322b5_hook: %x\n", npdrm_723322b5_hook_id);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
  }

  if(npdrm_41daea12_hook_id < 0)
  {
    snprintf(sprintfBuffer, 256, "failed to set npdrm_41daea12_hook: %x\n", npdrm_41daea12_hook_id);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
  }

  return 0;
}

int deinitialize_hooks()
{
  if(npdrm_723322b5_hook_id >= 0)
    taiHookReleaseForKernel(npdrm_723322b5_hook_id, npdrm_723322b5_hook_ref);

  if(npdrm_41daea12_hook_id >= 0)
    taiHookReleaseForKernel(npdrm_41daea12_hook_id, npdrm_41daea12_hook_ref);

  return 0;
}

int module_start(SceSize argc, const void *args) 
{
  FILE_GLOBAL_WRITE_LEN("Startup rif key decryptor\n");

  initialize_hooks();

  decrypt();

  return SCE_KERNEL_START_SUCCESS;
}
 
//Alias to inhibit compiler warning
void _start() __attribute__ ((weak, alias ("module_start")));
 
int module_stop(SceSize argc, const void *args) 
{
  deinitialize_hooks();

  return SCE_KERNEL_STOP_SUCCESS;
}