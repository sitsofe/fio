for i in {1..100}; do echo "Loop $i; $(date)"; ./fio hang.fio; if [[ $? -ne 0 ]]; then break; fi; done
for i in {1..150}; do echo "Loop $i; $(date)"; ./fio --eta=always hang.fio; if [[ $? -ne 0 ]]; then break; fi; done
