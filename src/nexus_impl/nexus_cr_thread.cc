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

      CrWorkItem wi = ctx.cr_req_queue->unlocked_pop();

      if (wi.wi_type == CrWorkItemType::kClientEncr) {

        aes_gcm_encrypt(wi.msg_buf->buf, wi.msg_buf->get_app_data_size());
        wi.req_out_queue->unlocked_push(wi.req_args);

      } else if (wi.wi_type == CrWorkItemType::kClientDecr) {

        aes_gcm_decrypt(wi.msg_buf->buf, wi.msg_buf->get_app_data_size());
        wi.cont_out_queue->unlocked_push(wi.cont_args);

      } else {

        throw std::runtime_error("CryptoWorkQueue: unrecognized payload type");

      }
    }
  }

  LOG_INFO("eRPC Nexus: Crypto Thread %zu exiting\n", ctx.cr_thread_index);
  return;
}

}  // namespace erpc
