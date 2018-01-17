FROM scratch

ADD bin/vaultcreds /vaultcreds

ENTRYPOINT ["/vaultcreds"]
CMD []