# Build image for the Android app (docs/ANDROID.md): JDK, Android SDK and NDK,
# Gradle and Go, all pinned. linux/amd64 because Google publishes the NDK and
# the build tools for x86-64 Linux only; on this Mac it runs emulated.
#
# The Go modules do not come from here: build.sh vendors them in the box (with
# its cooldown) and the build runs with GOPROXY=off. Gradle fetches the
# plugins and libraries from Google's Maven and Maven Central and checks each
# file against gradle/verification-metadata.xml.
FROM --platform=linux/amd64 eclipse-temurin:21-jdk-noble@sha256:4d271cd5e0624598cf563342f47281b09cb364bc13acbbd7251f49f83470018d

RUN apt-get update && apt-get install -y --no-install-recommends unzip ca-certificates curl \
	&& rm -rf /var/lib/apt/lists/*

# Command-line tools 20.0, checked here; sdkmanager then checks every package
# it installs against Google's repository manifest.
ENV ANDROID_HOME=/opt/android-sdk
RUN curl -fsSLo /tmp/clt.zip https://dl.google.com/android/repository/commandlinetools-linux-14742923_latest.zip \
	&& echo "48833c34b761c10cb20bcd16582129395d121b27  /tmp/clt.zip" | sha1sum -c - \
	&& mkdir -p $ANDROID_HOME/cmdline-tools && unzip -q /tmp/clt.zip -d $ANDROID_HOME/cmdline-tools \
	&& mv $ANDROID_HOME/cmdline-tools/cmdline-tools $ANDROID_HOME/cmdline-tools/latest && rm /tmp/clt.zip
RUN yes | $ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager --licenses >/dev/null \
	&& $ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager --install \
		"platforms;android-36" "build-tools;36.1.0" "ndk;29.0.14206865" "platform-tools" >/dev/null
ENV ANDROID_NDK_HOME=$ANDROID_HOME/ndk/29.0.14206865

RUN curl -fsSLo /tmp/gradle.zip https://services.gradle.org/distributions/gradle-9.7.1-bin.zip \
	&& echo "acd53f1edaf02f1a8ff99879f8a34b302661a057d9b063ae9e35b552f804d20a  /tmp/gradle.zip" | sha256sum -c - \
	&& unzip -q /tmp/gradle.zip -d /opt && ln -s /opt/gradle-9.7.1/bin/gradle /usr/local/bin/gradle && rm /tmp/gradle.zip

# the same Go as the box (go.mod)
RUN curl -fsSLo /tmp/go.tgz https://go.dev/dl/go1.26.7.linux-amd64.tar.gz \
	&& echo "ffb5f8de10c62550dfddab66b36b57030721e0a44a3218e9e1181d7b59f121ca  /tmp/go.tgz" | sha256sum -c - \
	&& tar -C /usr/local -xzf /tmp/go.tgz && rm /tmp/go.tgz
ENV PATH=/usr/local/go/bin:$PATH GOTOOLCHAIN=local GOPROXY=off GOFLAGS=-mod=vendor \
	GRADLE_USER_HOME=/cache/gradle GOCACHE=/cache/go
