#ifndef set_Verbose
  #define set_Verbose
#endif

#ifndef set_ForwardServerIP
  //#define set_ForwardServerIP 0x7f000001
  #define set_ForwardServerIP 0x01010101
#endif
#ifndef set_ForwardServerPort
  #define set_ForwardServerPort 53
#endif

#ifndef set_DNSQuery_Timeout
  #define set_DNSQuery_Timeout 20000000000
#endif

#include <WITCH/WITCH.h>

#include <WITCH/PR/PR.h>

#include <WITCH/IO/IO.h>
#include <WITCH/IO/print.h>

#include <WITCH/VEC/VEC.h>
#include <WITCH/VEC/print.h>

#include <WITCH/EV/EV.h>

void print(const char *format, ...){
  IO_fd_t fd_stdout;
  IO_fd_set(&fd_stdout, FD_OUT);
  va_list argv;
  va_start(argv, format);
  IO_vprint(&fd_stdout, format, argv);
  va_end(argv);
}

/* verbose error print */
#define VEP \
  print("problemo %lu\n", (uint32_t)__LINE__);

#pragma pack(push, 1)
  typedef struct{
    uint16_t AnswerRRs;
    uint16_t AuthorityRRs;
    uint16_t AdditionalRRs;
  }DNSSubHead_t;
  typedef struct{
    uint16_t TransactionID;
    uint16_t Flags;
    uint16_t Questions;
    DNSSubHead_t SubHead;
  }DNSHead_t;
  typedef struct{
    uint16_t Type;
    uint16_t Class;
  }DNSQueryHead_t;
#pragma pack(pop)

typedef struct{
  uint16_t ForwardTransactionID;
  uint16_t RecvTransactionID;
  NET_addr_t RecvAddress;
  EV_timer_t Timer;
}DNSQueryMap_Output_t;

#define MAP_set_Prefix DNSQueryMap
#define MAP_set_InputType uint16_t
#define MAP_set_OutputType DNSQueryMap_Output_t *
#define MAP_set_MaxInput 0xffffffff
#include <WITCH/MAP/MAP.h>

typedef struct{
  DNSSubHead_t SubHead;
  void *Data;
  uintptr_t Size;
}DNSCacheMap_Output_t;

#define MAP_set_Prefix DNSCacheMap
#define MAP_set_OutputType DNSCacheMap_Output_t
#define MAP_set_MaxInput 0xffffffff
#include <WITCH/MAP/MAP.h>

typedef struct{
  EV_t listener;

  uint16_t DNSForwardTransactionID;
  NET_socket_t DNSSocket;
  NET_socket_t DNSForwardSocket;
  EV_event_t DNSEvent;
  EV_event_t DNSForwardEvent;
  DNSQueryMap_t DNSQueryMap;
  DNSCacheMap_t DNSCacheMap;
}pile_t;
pile_t pile;

void RemoveDNSQuery(uint16_t TransactionID){
  DNSQueryMap_Output_t *dnso = *DNSQueryMap_GetOutputPointer(&pile.DNSQueryMap, &TransactionID);
  EV_timer_stop(&pile.listener, &dnso->Timer);
  A_resize(dnso, 0);
  DNSQueryMap_Remove(&pile.DNSQueryMap, &TransactionID);
}

void cb_DNSQueryTimer(EV_t *l, EV_timer_t *t){
  DNSQueryMap_Output_t *dnso = OFFSETLESS(t, DNSQueryMap_Output_t, Timer);
  RemoveDNSQuery(dnso->ForwardTransactionID);
}

void DNSGiveResponse(
  uint16_t TransactionID,
  DNSSubHead_t *DNSSubHead,
  uint8_t *dp,
  uintptr_t ds,
  void *Data,
  uintptr_t DataSize,
  NET_addr_t *addr
){
  VEC_t vec;
  VEC_init(&vec, 1, A_resize);

  DNSHead_t DNSHead;
  DNSHead.TransactionID = TransactionID;
  DNSHead.Flags = 0x0080;
  DNSHead.Questions = 0x0100;
  DNSHead.SubHead = *DNSSubHead;

  VEC_print(&vec, "%.*s", sizeof(DNSHead_t), &DNSHead);
  VEC_print(&vec, "%.*s%c", ds, dp, 0);
  VEC_print(&vec, "%c%c%c%c", 0, 1, 0, 1); /* Type, Class */

  VEC_print(&vec, "%.*s", DataSize, Data);

  NET_sendto(&pile.DNSSocket, vec.ptr, vec.Current, addr);

  VEC_free(&vec);
}

void cb_DNSForwardEvent(EV_t *l, EV_event_t *e, uint32_t f){
  NET_addr_t RecvAddress;
  uint8_t Data[0x800];
  IO_ssize_t DataSize = NET_recvfrom(&pile.DNSForwardSocket, Data, sizeof(Data), &RecvAddress);
  if(DataSize < 0){
    print("cb_DNSForwardEvent NET_recvfrom %d\n", DataSize);
    PR_abort();
  }
  else if(DataSize < sizeof(DNSHead_t)){
    return;
  }

  DNSHead_t *DNSHead = (DNSHead_t *)Data;

  uint16_t TransactionID = DNSHead->TransactionID;
  if(DNSQueryMap_GetOutputPointerSafe(&pile.DNSQueryMap, &TransactionID) == NULL){
    print("cb_DNSForwardEvent failed to find from DNSQueryMap %lx\n", TransactionID);
    return;
  }

  if(
    byteswap16(DNSHead->Questions) == 1 &&
    DNSHead->Flags & 0x0080 &&
    !(DNSHead->Flags & 0x0078)
  ); else{
    print("too complex dns response %lx %04lx\n", byteswap16(DNSHead->Questions), DNSHead->Flags);
    goto gt_BrokenResponse;
  }

  if(DNSHead->Flags & 0x0f00){
    print("not okay flags %04lx\n", DNSHead->Flags);
    goto gt_BrokenResponse;
  }

  {
    uintptr_t di = sizeof(DNSHead_t); /* domain index */
    uintptr_t i = di;
    for(; i < DataSize; i++){
      if(Data[i] == 0){
        break;
      }
    }

    if(i == di){
      /* no domain name? */
      VEP
      goto gt_BrokenResponse;
    }

    uintptr_t ds = i - di; /* domain size */

    if(DataSize - 1 - i < sizeof(DNSQueryHead_t)){
      VEP
      goto gt_BrokenResponse;
    }
    i++;

    DNSQueryHead_t *qh = (DNSQueryHead_t *)&Data[i];
    if(qh->Type != 0x0100 || qh->Class != 0x0100){
      print("type and class was %lx %04lx %04lx\n", DNSHead->TransactionID, qh->Type, qh->Class);
      VEP
      goto gt_BrokenResponse;
    }
    i += sizeof(DNSQueryHead_t);

    uintptr_t aqs = DataSize - i; /* after question size */

    if(aqs == 0){
      /* where is answer? */
      VEP
      goto gt_BrokenResponse;
    }

    if(DNSCacheMap_GetOutputPointerSafe(&pile.DNSCacheMap, &Data[di], ds) != NULL){
      /* pain in brain */
      print("double dns cache try came %.*s\n", ds, &Data[di]);
      goto gt_NoCache;
    }

    DNSCacheMap_Output_t cmo; /* cache map output */
    cmo.SubHead = DNSHead->SubHead;
    cmo.Size = aqs;
    cmo.Data = A_resize(NULL, cmo.Size);
    MEM_copy(&Data[i], cmo.Data, cmo.Size);
    DNSCacheMap_InNew(&pile.DNSCacheMap, &Data[di], ds, &cmo);
  }
  gt_NoCache:;

  DNSQueryMap_Output_t *dnso = *DNSQueryMap_GetOutputPointer(&pile.DNSQueryMap, &TransactionID);

  DNSHead->TransactionID = dnso->RecvTransactionID;

  NET_sendto(&pile.DNSSocket, Data, DataSize, &dnso->RecvAddress);

  gt_BrokenResponse:;
  RemoveDNSQuery(TransactionID);
}
void cb_DNSEvent(EV_t *l, EV_event_t *e, uint32_t f){
  NET_addr_t RecvAddress;
  uint8_t Data[0x800];
  IO_ssize_t DataSize = NET_recvfrom(&pile.DNSSocket, Data, sizeof(Data), &RecvAddress);
  if(DataSize < 0){
    PR_abort();
  }
  else if(DataSize < sizeof(DNSHead_t)){
    return;
  }

  DNSHead_t *DNSHead = (DNSHead_t *)Data;

  if(byteswap16(DNSHead->Questions) != 1){
    print("broken dns request %lx\n", byteswap16(DNSHead->Questions));
    goto gt_BrokenRequest;
  }

  {
    uintptr_t di = sizeof(DNSHead_t); /* domain index */
    uintptr_t ti = di; /* terminator index */
    for(; ti < DataSize; ti++){
      if(Data[ti] == 0){
        break;
      }
    }

    if(ti == di){
      /* no domain name? */
      goto gt_BrokenRequest;
    }

    uintptr_t ds = ti - di; /* domain size */

    DNSCacheMap_Output_t *cmo = DNSCacheMap_GetOutputPointerSafe(&pile.DNSCacheMap, &Data[di], ds);
    if(cmo == NULL){
      /* pain in brain */
      goto gt_NoCache;
    }

    DNSGiveResponse(DNSHead->TransactionID, &cmo->SubHead, &Data[di], ds, cmo->Data, cmo->Size, &RecvAddress);

    return;
  }
  gt_NoCache:;

  DNSQueryMap_Output_t *dnso = (DNSQueryMap_Output_t *)A_resize(NULL, sizeof(DNSQueryMap_Output_t));
  dnso->ForwardTransactionID = pile.DNSForwardTransactionID++;
  dnso->RecvTransactionID = DNSHead->TransactionID;
  dnso->RecvAddress = RecvAddress;
  EV_timer_init(&dnso->Timer, (f64_t)set_DNSQuery_Timeout / 1000000000, cb_DNSQueryTimer);
  EV_timer_start(&pile.listener, &dnso->Timer);

  if(DNSQueryMap_GetOutputPointerSafe(&pile.DNSQueryMap, &dnso->ForwardTransactionID) != NULL){
    RemoveDNSQuery(dnso->ForwardTransactionID);
  }

  DNSQueryMap_InNew(&pile.DNSQueryMap, &dnso->ForwardTransactionID, &dnso);

  DNSHead->TransactionID = dnso->ForwardTransactionID;

  NET_addr_t SendAddress;
  SendAddress.ip = set_ForwardServerIP;
  SendAddress.port = set_ForwardServerPort;
  NET_sendto(&pile.DNSForwardSocket, Data, DataSize, &SendAddress);

  gt_BrokenRequest:;
}

int main(){
  EV_open(&pile.listener);

  {
    pile.DNSForwardTransactionID = 0;

    sint32_t err = NET_socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP, &pile.DNSSocket);
    if(err != 0){
      PR_abort();
    }

    NET_addr_t addr;
    addr.ip = INADDR_ANY;
    addr.port = 53;
    err = NET_bind(&pile.DNSSocket, &addr);
    if(err != 0){
      PR_abort();
    }

    err = NET_socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP, &pile.DNSForwardSocket);
    if(err != 0){
      PR_abort();
    }

    EV_event_init_socket(&pile.DNSEvent, &pile.DNSSocket, cb_DNSEvent, EV_READ);
    EV_event_start(&pile.listener, &pile.DNSEvent);

    EV_event_init_socket(&pile.DNSForwardEvent, &pile.DNSForwardSocket, cb_DNSForwardEvent, EV_READ);
    EV_event_start(&pile.listener, &pile.DNSForwardEvent);

    DNSQueryMap_Open(&pile.DNSQueryMap);

    DNSCacheMap_Open(&pile.DNSCacheMap);
  }

  EV_start(&pile.listener);

  return 0;
}
