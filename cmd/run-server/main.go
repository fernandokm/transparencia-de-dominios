package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	dt "github.com/fernandokm/transparencia-de-dominios"
	ds "github.com/fernandokm/transparencia-de-dominios/server"
	"github.com/fernandokm/transparencia-de-dominios/util"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/google/certificate-transparency-go/loglist2"
)

var (
	cmd = flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	privatePEM        = cmd.String("private_key", "config/privatekey.pem", "the pem file with this map's private key (the file will be created if missing)")
	publicPEM         = cmd.String("public_key", "config/publickey.pem", "the pem file with this map's public key (the file will be created if missing)")
	ip                = cmd.String("ip", "127.0.0.1", "the IP address on which to run the server")
	port              = cmd.Uint("port", 8021, "the port address on which to run the server")
	smhUpdateInterval = cmd.Duration("smh_interval", 5*time.Second, "how often to try to publish SMHs")
	sthUpdateInterval = cmd.Duration("sth_interval", 5*time.Second, "how often to check for STH updates")
	mmd               = cmd.Duration("mmd", 60*time.Second, "the max interval between SMHs")

	logSpecifiers stringSliceFlags
)

func init() {
	cmd.Var(&logSpecifiers, "log", "a log from which to pull map updates (by name, url or hash). This log must be listed in the loglist.json file. If empty, use preset data. (repeatable)")

	// Remove glog output
	flag.Set("logtostderr", "false")
	flag.Set("stderrthreshold", "FATAL")
	flag.CommandLine.Parse([]string{})
}

func main() {
	cmd.Parse(os.Args[1:])

	key, err := loadOrGenerateKeys(*privatePEM, *publicPEM)
	if err != nil {
		fmt.Printf("Error creating or loading key: %v\n", err)
		return
	}

	dm := dt.NewDomainMap(key)
	svr, _ := ds.NewServer(dm, *ip, int(*port))
	ctx, cancel := context.WithCancel(context.Background())
	c, stopped := dt.StartWorker(ctx, dm, dt.WorkerConfig{
		BufferSize:   32,
		UpdatePeriod: *smhUpdateInterval,
		MMD:          *mmd,
	})

	if len(logSpecifiers) == 0 {
		fmt.Printf("No logs specified\n")
		return
	} else {
		timestamps, logClients, err := specsToLogs(logSpecifiers)
		if err != nil {
			fmt.Printf("Error creating log fetchers: %s\n", err)
			return
		}
		for i, lc := range logClients {
			t := timestamps[i]
			go fetcherData(ctx, t, dm, c, lc, uint64(i))
		}
	}

	go func() {
		fmt.Printf("Starting server on %s\n", svr.Addr)
		if err = svr.ListenAndServe(); err != nil {
			fmt.Printf("Server error: %v\n", err)
		}
	}()

	handleInterrupts(cancel, svr, stopped)
}

func specsToLogs(specs []string) ([]time.Time, []*loglist2.Log, error) {
	logClients := make([]*loglist2.Log, len(specs))
	timestamps := make([]time.Time, len(specs))
	var err error
	for i, logSpec := range specs {
		timestamps[i], logClients[i], err = specToLog(logSpec)
		if err != nil {
			return nil, nil, err
		}
	}
	return timestamps, logClients, nil
}

func specToLog(logSpec string) (time.Time, *loglist2.Log, error) {
	t := time.Now()
	if parts := strings.SplitN(logSpec, ":", 2); len(parts) == 2 {
		if v, err := strconv.ParseInt(parts[0], 10, 64); err == nil {
			logSpec = parts[1]
			t = t.Add(time.Duration(v) * time.Second)
		}
	}
	logs := util.FindLogs(logSpec)
	if len(logs) > 1 {
		return t, nil, fmt.Errorf("ambiguous log specifier %q: got %d matches", logSpec, len(logs))
	} else if len(logs) == 0 {
		return t, nil, fmt.Errorf("specifier %q was not found in the loglist", logSpec)
	}
	return t, logs[0], nil
}

func fetcherData(ctx context.Context, t time.Time, dm *dt.DomainMap, c chan<- dt.WorkerTransaction, logData *loglist2.Log, logIndex uint64) {
	// Wait until log is active
	// If t <= time.Now(), time.Sleep() will return immediately
	time.Sleep(time.Until(t))

	fmt.Printf("Tracking log %d: %s\n", logIndex, logData.URL)

	lc, err := client.New(logData.URL, http.DefaultClient, jsonclient.Options{PublicKeyDER: logData.Key})
	if err != nil {
		log.Panicf("Unexpected error creating log client: %v", err)
	}
	params := ds.FetchParams{
		InitialTreeSize:  0,
		STHCheckInterval: *sthUpdateInterval,
		LogIndex:         logIndex,
		LogClient:        lc,
		C:                c,
		ReturnOnError:    false,
	}
	copy(params.LogID[:], logData.LogID)
	if err := ds.FetchLogForWorker(context.Background(), params); err != nil {
		fmt.Printf("Fetcher error: %s\n", err)
	}
}

func handleInterrupts(cancel context.CancelFunc, svr *http.Server, svrStopped <-chan struct{}) {
	c := make(chan os.Signal, 10)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM, syscall.SIGBUS, syscall.SIGPIPE)

	for {
		select {
		case <-c:
			fmt.Println("Stopping workers...")
			cancel()

		case <-svrStopped:
			signal.Stop(c)
			goto shutdown
		}
	}
shutdown:
	fmt.Println("Shutting down server... Press Ctrl+C again to force quit")
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(time.Minute))
	defer cancel()
	if err := svr.Shutdown(ctx); err != nil {
		fmt.Printf("Shutdown error: %v\n", err)
	}
}
