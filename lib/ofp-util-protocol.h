/*
 * Copyright (c) 2014 Nicira, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef OFP_UTIL_PROTOCOL_H
#define OFP_UTIL_PROTOCOL_H 1


/* Protocols.
 *
 * A "protocol" is an OpenFlow version plus, for some OpenFlow versions,
 * a bit extra about the flow match format in use.
 *
 * These are arranged from most portable to least portable, or alternatively
 * from least powerful to most powerful.  Protocols earlier on the list are
 * more likely to be understood for the purpose of making requests, but
 * protocol later on the list are more likely to accurately describe a flow
 * within a switch.
 *
 * On any given OpenFlow connection, a single protocol is in effect at any
 * given time.  These values use separate bits only because that makes it easy
 * to test whether a particular protocol is within a given set of protocols and
 * to implement set union and intersection.
 */
enum ofputil_protocol {
    /* OpenFlow 1.0 protocols.
     *
     * The "STD" protocols use the standard OpenFlow 1.0 flow format.
     * The "NXM" protocols use the Nicira Extensible Match (NXM) flow format.
     *
     * The protocols with "TID" mean that the nx_flow_mod_table_id Nicira
     * extension has been enabled.  The other protocols have it disabled.
     */
#define OFPUTIL_P_NONE 0
    OFPUTIL_P_OF10_STD     = 1 << 0,
    OFPUTIL_P_OF10_STD_TID = 1 << 1,
    OFPUTIL_P_OF10_NXM     = 1 << 2,
    OFPUTIL_P_OF10_NXM_TID = 1 << 3,
#define OFPUTIL_P_OF10_STD_ANY (OFPUTIL_P_OF10_STD | OFPUTIL_P_OF10_STD_TID)
#define OFPUTIL_P_OF10_NXM_ANY (OFPUTIL_P_OF10_NXM | OFPUTIL_P_OF10_NXM_TID)
#define OFPUTIL_P_OF10_ANY (OFPUTIL_P_OF10_STD_ANY | OFPUTIL_P_OF10_NXM_ANY)

    /* OpenFlow 1.1 protocol.
     *
     * We only support the standard OpenFlow 1.1 flow format.
     *
     * OpenFlow 1.1 always operates with an equivalent of the
     * nx_flow_mod_table_id Nicira extension enabled, so there is no "TID"
     * variant. */
    OFPUTIL_P_OF11_STD     = 1 << 4,

    /* OpenFlow 1.2+ protocols (only one variant each).
     *
     * These use the standard OpenFlow Extensible Match (OXM) flow format.
     *
     * OpenFlow 1.2+ always operates with an equivalent of the
     * nx_flow_mod_table_id Nicira extension enabled, so there is no "TID"
     * variant. */
    OFPUTIL_P_OF12_OXM      = 1 << 5,
    OFPUTIL_P_OF13_OXM      = 1 << 6,
    OFPUTIL_P_OF14_OXM      = 1 << 7,
    OFPUTIL_P_OF15_OXM      = 1 << 8,
#define OFPUTIL_P_ANY_OXM (OFPUTIL_P_OF12_OXM | \
                           OFPUTIL_P_OF13_OXM | \
                           OFPUTIL_P_OF14_OXM | \
                           OFPUTIL_P_OF15_OXM)

#define OFPUTIL_P_NXM_OF11_UP (OFPUTIL_P_OF10_NXM_ANY | OFPUTIL_P_OF11_STD | \
                               OFPUTIL_P_ANY_OXM)

#define OFPUTIL_P_NXM_OXM_ANY (OFPUTIL_P_OF10_NXM_ANY | OFPUTIL_P_ANY_OXM)

#define OFPUTIL_P_OF11_UP (OFPUTIL_P_OF11_STD | OFPUTIL_P_ANY_OXM)

#define OFPUTIL_P_OF12_UP (OFPUTIL_P_OF12_OXM | OFPUTIL_P_OF13_UP)
#define OFPUTIL_P_OF13_UP (OFPUTIL_P_OF13_OXM | OFPUTIL_P_OF14_UP)
#define OFPUTIL_P_OF14_UP (OFPUTIL_P_OF14_OXM | OFPUTIL_P_OF15_UP)
#define OFPUTIL_P_OF15_UP OFPUTIL_P_OF15_OXM

    /* All protocols. */
#define OFPUTIL_P_ANY ((1 << 9) - 1)

    /* Protocols in which a specific table may be specified in flow_mods. */
#define OFPUTIL_P_TID (OFPUTIL_P_OF10_STD_TID | \
                       OFPUTIL_P_OF10_NXM_TID | \
                       OFPUTIL_P_OF11_STD |     \
                       OFPUTIL_P_ANY_OXM)
};

#endif /* ofp-util-protocol.h */
