http://159.89.20.141:8080

ssh root@159.89.20.141

http://159.89.20.141:81



## Ligar o Argo CD
kubectl port-forward svc/argocd-server -n argocd 8080:443                                                      