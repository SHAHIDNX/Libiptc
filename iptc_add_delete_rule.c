#include <string.h>
#include <ctype.h>
#include <sys/types.h>

#include<libiptc/libiptc.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/time.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <linux/netfilter/x_tables.h>
void iptc_add_rule(const char *table, const char *chain, const char *protocol, const char *iiface, const char *oiface, const char *src, const char *dest, const char *srcports, const char *destports, const char *target, const char *dnat_to, const int append);

void iptc_delete_rule(const char *table, const char *chain, const char *protocol, const char *iniface, const char *outiface, const char *src, const char *dest, const char *srcports, const char *destports, const char *target, const char *dnat_to,int indx);
struct ipt_entry_match *get_udp_match(const char *sports, const char *dports, unsigned int *nfcache);
static u_int16_t parse_port(const char *port);
static void parse_ports(const char *portstring, u_int16_t *ports);

#ifndef IPT_MIN_ALIGN
/* ipt_entry has pointers and u_int64_t's in it, so if you align to
 *    it, you'll also align to any crazy matches and targets someone
 *       might write */
#define IPT_MIN_ALIGN (__alignof__(struct ipt_entry))
#endif

#define IPT_ALIGN(s) (((s) + ((IPT_MIN_ALIGN)-1)) & ~((IPT_MIN_ALIGN)-1))


#define IPTC_ENTRY_SIZE XT_ALIGN(sizeof(struct ipt_entry))
#define IPTC_MATCH_SIZE XT_ALIGN(sizeof(struct ipt_entry_match) + sizeof(struct ipt_udp))
#define IPTC_TARGET_SIZE XT_ALIGN(sizeof(struct ipt_entry_target))

#define IPTC_FULL_SIZE IPTC_ENTRY_SIZE + IPTC_MATCH_SIZE + IPTC_TARGET_SIZE

        int
main(int argc, char *argv[])
{

        if (argc < 2 )
                printf ("Argv: 1.Operation(ADD:1, DEL:2");

        int operation = atoi(argv[1]);

        unsigned int destIp;


         inet_pton (AF_INET, "10.201.0.238", &destIp);
         if (operation == 1)
                 iptc_add_rule("filter","INPUT","UDP",NULL,NULL,NULL,destIp,NULL,"8000","ACCEPT",NULL,NULL);
         else
                 my_iptc_delete_rule("filter","INPUT","UDP",NULL,NULL,NULL,destIp,NULL,"8000","ACCEPT",NULL,NULL);

}

void iptc_add_rule(const char *table, const char *chain, const char *protocol, const char *iniface, const char *outiface, const char *src, const char *dest, const char *srcports, const char *destports, const char *target, const char *dnat_to, const int append) {
        struct xtc_handle * handle;
        struct ipt_entry *chain_entry;
        struct ipt_entry_match *entry_match = NULL;
        struct ipt_entry_target *entry_target;
        ipt_chainlabel labelit;
        long match_size;
        int result = 0;

        chain_entry = (struct ipt_entry *) calloc(1, sizeof (*chain_entry));

        if (src) {
                chain_entry->ip.src.s_addr = src;
                chain_entry->ip.smsk.s_addr = 0xFFFFFFFF;// inet_addr("255.255.255.255");
        }
        if (dest) {
                chain_entry->ip.dst.s_addr = dest;
                chain_entry->ip.dmsk.s_addr = 0xFFFFFFFF;// inet_addr("255.255.255.255");
        }

        if (iniface) strncpy(chain_entry->ip.iniface, iniface, IFNAMSIZ);
        if (outiface) strncpy(chain_entry->ip.outiface, outiface, IFNAMSIZ);

        chain_entry->ip.proto = IPPROTO_UDP;
        entry_match = get_udp_match(srcports, destports, &chain_entry->nfcache);

        if (strcmp(target, "") == 0
                        || strcmp(target, IPTC_LABEL_ACCEPT) == 0
                        || strcmp(target, IPTC_LABEL_DROP) == 0
                        || strcmp(target, IPTC_LABEL_QUEUE) == 0
                        || strcmp(target, IPTC_LABEL_RETURN) == 0) {
                size_t size;

                size = IPT_ALIGN(sizeof (struct ipt_entry_target)) + IPT_ALIGN(sizeof (int));
                entry_target = (struct ipt_entry_target *) calloc(1, size);
                entry_target->u.user.target_size = size;
                strncpy(entry_target->u.user.name, target, IPT_FUNCTION_MAXNAMELEN);
        }
        if (entry_match)
        {
                match_size = entry_match->u.match_size;
        }
        else
                match_size = 0;

        struct ipt_entry *tmp_ipt = chain_entry;
        chain_entry = (struct ipt_entry *) realloc(chain_entry, sizeof (*chain_entry) + match_size + entry_target->u.target_size);
        if (chain_entry == NULL) {
                free(tmp_ipt);
        }
        memcpy(chain_entry->elems + match_size, entry_target, entry_target->u.target_size);
        chain_entry->target_offset = sizeof (*chain_entry) + match_size;
        chain_entry->next_offset = sizeof (*chain_entry) + match_size + entry_target->u.target_size;
        if (entry_match) {
                memcpy(chain_entry->elems, entry_match, match_size);
        }
        handle = iptc_init(table);
        if (!handle) {
                printf("libiptc error: Can't initialize table %s, %s", table, iptc_strerror(errno));
                free(chain_entry);
                free(entry_target);
                if (entry_match) free(entry_match);
                return;
        }

        strncpy(labelit, chain, sizeof (ipt_chainlabel));
        printf ("Chain name:%s\n",chain);
        result = iptc_is_chain(chain, handle);
        if (!result) {
                printf("libiptc error: Chain %s does not exist!", chain);
                free(chain_entry);
                free(entry_target);
                if (entry_match) free(entry_match);
                return;
        }
        if (append)
                result = iptc_append_entry(labelit, chain_entry, handle);
        else
                result = iptc_insert_entry(labelit, chain_entry, 0, handle);
        if (!result) {
                printf("libiptc error: Can't add, %s", iptc_strerror(errno));
                free(chain_entry);
                free(entry_target);
                if (entry_match) free(entry_match);
                return;
        }
        result = iptc_commit(handle);
        if (!result) {
                printf("libiptc error: Commit error, %s", iptc_strerror(errno));
                free(chain_entry);
                free(entry_target);
                if (entry_match) free(entry_match);
                return;
        }

        if (entry_match) free(entry_match);
        free(entry_target);
        free(chain_entry);
}


static void
parse_ports(const char *portstring, u_int16_t *ports) {
        char *buffer;
        char *cp;

        buffer = strdup(portstring);
        if ((cp = strchr(buffer, ':')) == NULL)
                ports[0] = ports[1] = parse_port(buffer);
        else {
                *cp = '\0';
                cp++;

                ports[0] = buffer[0] ? parse_port(buffer) : 0;
                ports[1] = cp[0] ? parse_port(cp) : 0xFFFF;
        }
        free(buffer);
}

struct ipt_entry_match *
get_udp_match(const char *sports, const char *dports, unsigned int *nfcache) {
        struct ipt_entry_match *match;
        struct ipt_udp *udpinfo;
        size_t size;

        size = IPT_ALIGN(sizeof (*match)) + IPT_ALIGN(sizeof (*udpinfo));
        match = (struct ipt_entry_match *) calloc(1, size);
        match->u.match_size = size;
        strncpy(match->u.user.name, "udp", IPT_FUNCTION_MAXNAMELEN);

        udpinfo = (struct ipt_udp *) match->data;
        udpinfo->spts[1] = udpinfo->dpts[1] = 0xFFFF;
        //printf("sports=%s,dports=%s\n", sports, dports);
        if (sports) {
                *nfcache |= NFC_IP_SRC_PT;
                parse_ports(sports, udpinfo->spts);
        }
        if (dports) {
                *nfcache |= NFC_IP_DST_PT;
                parse_ports(dports, udpinfo->dpts);
        }

        return match;
}


static u_int16_t
parse_port(const char *port) {

        return atoi(port);
}

void my_iptc_delete_rule(const char *table, const char *chain, const char *protocol, const char *iniface, const char *outiface, const char *src, const char *dest, const char *srcports, const char *destports, const char *target, const char *dnat_to, const int append) {
        struct xtc_handle * handle;
        struct ipt_entry *chain_entry;
        struct ipt_entry_match *entry_match = NULL;
        struct ipt_entry_target *entry_target;
        ipt_chainlabel labelit;
        long match_size;
        int result = 0;

        chain_entry = (struct ipt_entry *) calloc(1, sizeof (*chain_entry));

        if (src) {
                chain_entry->ip.src.s_addr = src;
                chain_entry->ip.smsk.s_addr = 0xFFFFFFFF;// inet_addr("255.255.255.255");
        }
        if (dest) {
                chain_entry->ip.dst.s_addr = dest;
                chain_entry->ip.dmsk.s_addr = 0xFFFFFFFF;// inet_addr("255.255.255.255");
        }

        if (iniface) strncpy(chain_entry->ip.iniface, iniface, IFNAMSIZ);
        if (outiface) strncpy(chain_entry->ip.outiface, outiface, IFNAMSIZ);

        chain_entry->ip.proto = IPPROTO_UDP;
        entry_match = get_udp_match(srcports, destports, &chain_entry->nfcache);
        if (strcmp(target, "") == 0
                        || strcmp(target, IPTC_LABEL_ACCEPT) == 0
                        || strcmp(target, IPTC_LABEL_DROP) == 0
                        || strcmp(target, IPTC_LABEL_QUEUE) == 0
                        || strcmp(target, IPTC_LABEL_RETURN) == 0) {
                size_t size;
                size = IPT_ALIGN(sizeof (struct ipt_entry_target)) + IPT_ALIGN(sizeof (int));
                entry_target = (struct ipt_entry_target *) calloc(1, size);
                entry_target->u.user.target_size = size;
                strncpy(entry_target->u.user.name, target, IPT_FUNCTION_MAXNAMELEN);
        }
        if (entry_match)
        {
                match_size = entry_match->u.match_size;
        }
        else
                match_size = 0;

        struct ipt_entry *tmp_ipt = chain_entry;
        chain_entry = (struct ipt_entry *) realloc(chain_entry, sizeof (*chain_entry) + match_size + entry_target->u.target_size);
        if (chain_entry == NULL) {
                free(tmp_ipt);
        }
        memcpy(chain_entry->elems + match_size, entry_target, entry_target->u.target_size);
        chain_entry->target_offset = sizeof (*chain_entry) + match_size;
        chain_entry->next_offset = sizeof (*chain_entry) + match_size + entry_target->u.target_size;

        if (entry_match) {
                memcpy(chain_entry->elems, entry_match, match_size);
                //        printf("%d\n", __LINE__);
        }
        handle = iptc_init(table);
        if (!handle) {
                printf("libiptc error: Can't initialize table %s, %s", table, iptc_strerror(errno));
                free(chain_entry);
                free(entry_target);
                if (entry_match) free(entry_match);
                return;
        }

        strncpy(labelit, chain, sizeof (ipt_chainlabel));
        result = iptc_is_chain(chain, handle);
        if (!result) {
                printf("libiptc error: Chain %s does not exist!", chain);
                free(chain_entry);
                free(entry_target);
                if (entry_match) free(entry_match);
                return;
        }

        unsigned char matchmask[IPTC_FULL_SIZE];
        memset(matchmask, 255, IPTC_FULL_SIZE);

        result = iptc_delete_entry(chain, chain_entry ,matchmask, handle);
        if (!result) {
                printf("libiptc error: Delete error, %s", iptc_strerror(errno));
                return;
        }

        if (!result) {
                printf("libiptc error: Can't add, %s", iptc_strerror(errno));
                free(chain_entry);
                free(entry_target);
                if (entry_match) free(entry_match);
                return;
        }

        result = iptc_commit(handle);

        if (!result) {
                printf("libiptc error: Commit error, %s", iptc_strerror(errno));
                free(chain_entry);
                free(entry_target);
                if (entry_match) free(entry_match);
                return;
        }

        if (entry_match) free(entry_match);
        free(entry_target);
        free(chain_entry);
}
