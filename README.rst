This is a fork of the original project at `https://github.com/ValvePython/steam <https://github.com/ValvePython/steam>`_. This supports WebSocket based connections while keeping the original API in tact. 

For details about the library, refer to the original project.

---

Install latest release version of this fork from PYPI:

.. code:: bash

    # with SteamClient dependecies
    pip install -U "steam-rv[client]"

    # without (only when using parts that do no rely on gevent, and protobufs)
    pip install -U steam-rv
