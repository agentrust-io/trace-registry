FROM gcr.io/oss-fuzz-base/base-builder-python

COPY . $SRC/trace-registry
COPY .clusterfuzzlite/build.sh $SRC/build.sh
WORKDIR $SRC/trace-registry
