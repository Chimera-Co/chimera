import click

from .check_root import check_root


@click.command(
    help="Start the Android dynamic-analysis worker (Android guest + MobSF in the mobile VM)"
)
@click.option(
    "--burst", is_flag=True, default=False, help="Process queued jobs then exit"
)
@check_root
def mobile_worker(burst: bool):
    from drakrun.analyzer.mobile.worker import mobile_worker_main

    mobile_worker_main(burst=burst)
