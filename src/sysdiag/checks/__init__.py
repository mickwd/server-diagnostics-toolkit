"""Checks incluidos en el toolkit. Importar el paquete los registra."""

from sysdiag.checks import events, network, services, system, tls, updates

__all__ = ["events", "network", "services", "system", "tls", "updates"]
