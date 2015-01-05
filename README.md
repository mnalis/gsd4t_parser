Samsung Galaxy S2 uses <A HREF="http://redmine.replicant.us/projects/replicant/wiki/GSD4t">GSD4t</A> GPS chipset,
which does not use regular SiRF binary protocol, but some new variant, which is not yet supported by gpsd 
(as of 2014-06-22 gpsd v.3.10+dev3~d6b65b48-1)

The aim of this project is to create helpful scripts and instructions to help reverse engineer the new protocol, 
and make a converter to regular SiRF binary protocol (or NMEA).

As of 2015-01-05, much of the data has been reverse engineered, and it seems
that the hardware is really dumb; so all processing (downloading ephemeris,
calculation pseudoranges, solving GPS location etc.) would have to be done
completely in software.

Latest version can be found at <A HREF="https://github.com/mnalis/gsd4t_parser.git">GitHub</A>

You may also be interested in <A HREF="https://github.com/mnalis/gsd4t_logs.git">sample logs</A> if you lack your own...
