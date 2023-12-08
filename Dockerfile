FROM alpine:3 as base

RUN apk add -U --no-cache ca-certificates

FROM scratch

COPY --chmod=755 bin/vaultcreds /vaultcreds

COPY --from=base /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

ENTRYPOINT ["/vaultcreds"]
CMD []
