FROM debian:latest

ADD bin/vaultcreds /vaultcreds

ENTRYPOINT ["/vaultcreds"]
CMD []