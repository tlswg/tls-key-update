/* DTLS 1.3 EKU: fixed client initiator and server responder.
 * The shared engine models record-specific ACKs, local PHA state, exporter
 * generations, and CID processing. See SPEC-MAPPING.md and VERIFICATION.md.
 */
#ifndef INITIATE_A
#define INITIATE_A 1
#endif
#ifndef INITIATE_B
#define INITIATE_B 0
#endif
#ifndef INIT_RX_I
#define INIT_RX_I 0
#endif
#ifndef INIT_TX_I
#define INIT_TX_I INIT_RX_I
#endif
#ifndef INIT_RX_R
#define INIT_RX_R INIT_RX_I
#endif
#ifndef INIT_TX_R
#define INIT_TX_R INIT_RX_I
#endif
#if INIT_RX_I != INIT_TX_I || INIT_RX_I != INIT_RX_R || INIT_RX_I != INIT_TX_R
#error All initial directional epochs must match
#endif
#define INITIAL_A INIT_RX_I
#define INITIAL_B INIT_RX_R
#ifdef PHA_TRIGGER_R
#define PHA_TRIGGER_B PHA_TRIGGER_R
#endif
#ifdef EA_TRIGGER_I
#define EA_TRIGGER_A EA_TRIGGER_I
#endif
#ifdef EA_TRIGGER_R
#define EA_TRIGGER_B EA_TRIGGER_R
#endif
#ifdef EA_SPONT_TRIGGER_R
#define EA_SPONT_TRIGGER_B EA_SPONT_TRIGGER_R
#endif
#ifdef APP_QUOTA_I
#define APP_QUOTA_A APP_QUOTA_I
#endif
#ifdef APP_QUOTA_R
#define APP_QUOTA_B APP_QUOTA_R
#endif
#include "eku_protocol.pml"
