/* DTLS 1.3 EKU with simultaneous initiation and key-share tie-breaking.
 * Both roles continue serving post-handshake operations after local EKU
 * completion. The shared engine is also used by the single-initiator model.
 */
#ifndef INIT_RX_A
#define INIT_RX_A 0
#endif
#ifndef INIT_TX_A
#define INIT_TX_A INIT_RX_A
#endif
#ifndef INIT_RX_B
#define INIT_RX_B INIT_RX_A
#endif
#ifndef INIT_TX_B
#define INIT_TX_B INIT_RX_A
#endif
#if INIT_RX_A != INIT_TX_A || INIT_RX_A != INIT_RX_B || INIT_RX_A != INIT_TX_B
#error All initial directional epochs must match
#endif
#define INITIAL_A INIT_RX_A
#define INITIAL_B INIT_RX_B
#include "eku_protocol.pml"
