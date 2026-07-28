package web

import "net/http"

// SourceURL is where the source of this build can be obtained.
//
// The AGPL asks that anyone interacting with the program over a network be
// able to get its source. A self-hosted server has no way to know where its
// own source lives, so whoever builds it says:
//
//	go build -ldflags "-X synsec/internal/web.SourceURL=https://exemple/synsec" ./cmd/synsec
//
// Left empty, the page below says plainly that the operator has not set it,
// which is more useful than a link that goes nowhere.
var SourceURL = ""

// Version is stamped the same way, so the page can name the build whose source
// is being asked for.
var Version = "dev"

// showSource displays the licence notice and where to get the code.
//
// Reachable without signing in, and rendered outside the signed-in shell: the
// obligation is towards anyone the server interacts with, and a page that
// required an account would not discharge it.
func (s *Server) showSource(w http.ResponseWriter, r *http.Request) {
	data := pageData{
		Title:     "Licence et source",
		SourceURL: SourceURL,
	}

	// The build number is withheld from anonymous visitors. The licence is
	// owed to anyone; knowing which release is running only helps someone
	// matching a server against a list of known flaws.
	if _, _, _, ok := s.currentSession(r); ok {
		data.Version = Version
	}
	s.render(w, r, "source.html", http.StatusOK, data)
}
