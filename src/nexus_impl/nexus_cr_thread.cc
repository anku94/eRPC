#include "common.h"
#include "nexus.h"
#include "rpc_types.h"

namespace erpc {

void Nexus::cr_thread_func(CrThreadCtx ctx) {
  LOG_INFO("eRPC Nexus: Crypto Thread %zu running\n", ctx.cr_thread_index);

  while (*ctx.kill_switch == false) {
    if (ctx.cr_req_queue->size == 0) {
      continue;
    }

    while (ctx.cr_req_queue->size > 0) {
      LOG_INFO("eRPC Nexus: Crypto %zu Alert, jobs on queue\n",
               ctx.cr_thread_index);
    }
  }
  LOG_INFO("eRPC Nexus: Crypto Thread %zu exiting\n", ctx.cr_thread_index);
  return;
}

}  // namespace erpc
