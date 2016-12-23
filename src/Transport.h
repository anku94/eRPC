#ifndef ERPC_TRANSPORT_H
#define ERPC_TRANSPORT_H

#include "Common.h"
#include "Session.h"
#include "TransportTypes.h"

namespace ERpc {

// Generic transport class
class Transport {
public:
  Transport();
  ~Transport();

  /**
   * @brief Resolve the transport-specific fields of \p session by talking
   * to the remote host.
   */
  virtual void resolveSession(Session &session);

  virtual void sendMessage(Session &session);
  virtual void pollCompletions();

  TransportType type;
};

} // End ERpc

#endif // ERPC_TRANSPORT_H