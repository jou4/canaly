import threading
import time

import plotext as plt
from rich.live import Live
from rich.table import Table
from rich.text import Text
from rich.panel import Panel
from rich import box

from canaly import MonitoringItem


UPDATE_CYCLE_SEC = 0.1
GRAPH_W = 100
GRAPH_H = 6
Y_LABEL_W = 6
REFRESH_HZ  = 4


def make_graph(item):
    history = list(item.history())

    plt.clear_figure()
    plt.plot_size(GRAPH_W, GRAPH_H)
    plt.plot(history, color="blue+")

    min_val = item.min()
    max_val = item.max()
    if min_val == max_val:
        max_val = min_val + 1

    plt.ylim(min_val, max_val)

    plt.xaxes(False)
    plt.xticks([])

    ytick_vals = [min_val, max_val]
    ytick_labels = [f"{v:{Y_LABEL_W}.1f}" for v in ytick_vals]

    plt.yaxes(True)
    plt.yticks(ytick_vals, ytick_labels)

    plt.frame(True)

    return Text.from_ansi(plt.build())


def make_table(monitoring_fields, bits=False):
    table = Table(
        box=box.SIMPLE,
        show_header=True,
        header_style="bold cyan",
        padding=(0, 1),
    )
    table.add_column("Signal", style="cyan", width=30)
    table.add_column("Current", width=10)
    table.add_column("Chart", width=GRAPH_W + 2)

    # get keys in advance
    # to prevent dictionary size change during iteration
    names = monitoring_fields.keys()
    for name in names:
        item = monitoring_fields[name]
        table.add_row(
            name,
            ("0x%X" % (item.val())) if bits else f"{item.val()}",
            make_graph(item)
        )

    return Panel(table, title="[bold]CAN Signal Monitor[/bold]", border_style="bright_black")


def start_thread(monitoring_fields, bits=False):
    status = {
        "stop": False
    }

    def _target():
        with Live(make_table(monitoring_fields, bits), refresh_per_second=REFRESH_HZ, screen=False) as live:
            while not status["stop"]:
                for item in monitoring_fields.values():
                    item.update()

                live.update(make_table(monitoring_fields, bits))
                time.sleep(UPDATE_CYCLE_SEC)

            live.stop()

    t = threading.Thread(target=_target)
    t.start()

    def _stop():
        status["stop"] = True
        t.join()

    return _stop

