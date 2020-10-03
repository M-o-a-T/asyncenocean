# Async Python EnOcean #

An async Python library for reading and controlling [EnOcean](http://www.enocean.com/) devices.

# Usage #

The main `enocean` module exports SerialCommunicator and TCPCommunicator
clients.

```py
async with enocean.SerialCommunicator("/dev/ttyUSB0") as comm:
	async for p in comm.receive():
	    print(p)
```

You might want to test things by running `enocean_example.py` and pressing the
learn button on magnetic contact or temperature switch or pressing the rocker switch.

You should be displayed with a log of the presses, as well as parsed values
(assuming the sensors are the ones provided in the [EnOcean Starter Kit](https://www.enocean.com/en/enocean_modules/esk-300)).

The example script can be stopped by pressing `CTRL+C`; it will also
self-terminate after ten seconds of inactivity.
