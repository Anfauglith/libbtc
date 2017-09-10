#include "utest.h"
#include <iop/block.h>
#include <iop/net.h>
#include <iop/netspv.h>
#include <iop/utils.h>
#include <iop/serialize.h>
#include <iop/tx.h>

#include <unistd.h>

void test_spv_sync_completed(iop_spv_client* client) {
    printf("Sync completed, at height %d\n", client->headers_db->getchaintip(client->headers_db_ctx)->height);
    iop_node_group_shutdown(client->nodegroup);
}

iop_bool test_spv_header_message_processed(struct iop_spv_client_ *client, iop_node *node, iop_blockindex *newtip) {
    UNUSED(client);
    UNUSED(node);
    if (newtip) {
        printf("New headers tip height %d\n", newtip->height);
    }
    return true;
}

void test_netspv()
{
    unlink("headers.db");
    iop_spv_client* client = iop_spv_client_new(&iop_chainparams_main, true, false);
    client->header_message_processed = test_spv_header_message_processed;
    client->sync_completed = test_spv_sync_completed;

    iop_spv_client_load(client, "headers.db");

    printf("Discover peers...");
    iop_spv_client_discover_peers(client, NULL);
    printf("done\n");
    printf("Start interacting with the p2p network...\n");
    iop_spv_client_runloop(client);
    iop_spv_client_free(client);
}
