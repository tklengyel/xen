/*
 * drivers/char/xue.c
 *
 * Xen port for the xue debugger
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright (c) 2019 Assured Information Security.
 */

#include <xen/delay.h>
#include <xen/types.h>
#include <asm/string.h>
#include <asm/system.h>
#include <xen/serial.h>
#include <xen/timer.h>
#include <xen/param.h>
#include <asm/xue.h>

#define XUE_POLL_INTERVAL 100 /* us */

struct xue_uart {
    struct xue xue;
    struct timer timer;
    spinlock_t *lock;
};

static struct xue_uart xue_uart;
static struct xue_ops xue_ops;

static void xue_uart_poll(void *data)
{
    struct serial_port *port = data;
    struct xue_uart *uart = port->uart;
    struct xue *xue = &uart->xue;
    unsigned long flags = 0;

    if ( spin_trylock_irqsave(&port->tx_lock, flags) )
    {
        xue_flush(xue, &xue->dbc_oring, &xue->dbc_owork);
        spin_unlock_irqrestore(&port->tx_lock, flags);
    }

    serial_tx_interrupt(port, guest_cpu_user_regs());
    set_timer(&uart->timer, NOW() + MICROSECS(XUE_POLL_INTERVAL));
}

static void __init xue_uart_init_preirq(struct serial_port *port)
{
    struct xue_uart *uart = port->uart;
    uart->lock = &port->tx_lock;
}

static void __init xue_uart_init_postirq(struct serial_port *port)
{
    struct xue_uart *uart = port->uart;

    serial_async_transmit(port);
    init_timer(&uart->timer, xue_uart_poll, port, 0);
    set_timer(&uart->timer, NOW() + MILLISECS(1));
}

static int xue_uart_tx_ready(struct serial_port *port)
{
    struct xue_uart *uart = port->uart;
    struct xue *xue = &uart->xue;

    return XUE_WORK_RING_CAP - xue_work_ring_size(&xue->dbc_owork);
}

static void xue_uart_putc(struct serial_port *port, char c)
{
    struct xue_uart *uart = port->uart;
    xue_putc(&uart->xue, c);
}

static inline void xue_uart_flush(struct serial_port *port)
{
    s_time_t goal;
    struct xue_uart *uart = port->uart;
    struct xue *xue = &uart->xue;

    xue_flush(xue, &xue->dbc_oring, &xue->dbc_owork);

    goal = NOW() + MICROSECS(XUE_POLL_INTERVAL);
    if ( uart->timer.expires > goal )
        set_timer(&uart->timer, goal);
}

static struct uart_driver xue_uart_driver = {
    .init_preirq = xue_uart_init_preirq,
    .init_postirq = xue_uart_init_postirq,
    .endboot = NULL,
    .suspend = NULL,
    .resume = NULL,
    .tx_ready = xue_uart_tx_ready,
    .putc = xue_uart_putc,
    .flush = xue_uart_flush,
    .getc = NULL
};

static struct xue_trb evt_trb[XUE_TRB_RING_CAP] __aligned(XUE_PAGE_SIZE);
static struct xue_trb out_trb[XUE_TRB_RING_CAP] __aligned(XUE_PAGE_SIZE);
static struct xue_trb in_trb[XUE_TRB_RING_CAP] __aligned(XUE_PAGE_SIZE);
static struct xue_erst_segment erst __aligned(64);
static struct xue_dbc_ctx ctx __aligned(64);
static uint8_t wrk_buf[XUE_WORK_RING_CAP] __aligned(XUE_PAGE_SIZE);
static char str_buf[XUE_PAGE_SIZE] __aligned(64);

static char __initdata opt_dbgp[30];
string_param("dbgp", opt_dbgp);

void __init xue_uart_init(void)
{
    struct xue_uart *uart = &xue_uart;
    struct xue *xue = &uart->xue;

    if ( strncmp(opt_dbgp, "xue", 3) )
        return;

    memset(xue, 0, sizeof(*xue));
    memset(&xue_ops, 0, sizeof(xue_ops));

    xue->dbc_ctx = &ctx;
    xue->dbc_erst = &erst;
    xue->dbc_ering.trb = evt_trb;
    xue->dbc_oring.trb = out_trb;
    xue->dbc_iring.trb = in_trb;
    xue->dbc_owork.buf = wrk_buf;
    xue->dbc_str = str_buf;

    xue->dma_allocated = 1;
    xue->sysid = xue_sysid_xen;
    xue_open(xue, &xue_ops, NULL);

    serial_register_uart(SERHND_DBGP, &xue_uart_driver, &xue_uart);
}

void xue_uart_dump(void)
{
    struct xue_uart *uart = &xue_uart;
    struct xue *xue = &uart->xue;

    xue_dump(xue);
}
