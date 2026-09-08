# syntax=docker/dockerfile:1

# The `render` service's image: the server image, plus a browser.
#
# A layer on the shipped image rather than a build of its own. The binary is the
# same one every other service runs - `render` is a service name, not a separate
# program - so this adds the one thing that container needs and nothing else.
#
# It is separate because the browser is ~400 MB and one service uses it. Every
# other container would carry it for nothing, and the container that *does* run
# a renderer over pages strangers paste is the one worth being able to isolate,
# limit and restart on its own.

ARG STARLING_IMAGE=starling:local
FROM ${STARLING_IMAGE}

USER root

# Chromium from Debian rather than a downloaded build: it is what the
# distribution patches, and a preview service is not a place to be running an
# unpatched browser.
#
# The fonts are not decoration. A page rendered with no font at all can lay out
# differently enough that script-written metadata never appears, and the CJK and
# emoji faces are what stop a title becoming a row of boxes on the sites where
# that matters most.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      chromium \
      fonts-liberation \
      fonts-noto-core \
      fonts-noto-cjk \
      fonts-noto-color-emoji \
 && rm -rf /var/lib/apt/lists/*

# The service finds `/usr/bin/chromium` by itself: it is on the list of names it
# looks for and there is exactly one browser in this image. An operator who
# wants it stated rather than discovered writes it in starling.toml, which is
# where service options live:
#
#   [services.render.options]
#   browser_binary = "/usr/bin/chromium"
#
# Deliberately not an environment variable here: the environment mapping reaches
# endpoints and runtime settings, not `options`, so an `ENV` naming the browser
# would look like configuration and do nothing.

USER starling
WORKDIR /var/lib/starling
