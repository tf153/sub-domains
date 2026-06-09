// Package takeover provides heuristic detection of dangling CNAME records that
// may allow subdomain takeover. A host is flagged when it CNAMEs to a known
// third-party service but the underlying target does not resolve (NXDOMAIN) or
// returns a known "unclaimed" fingerprint.
//
// This is a heuristic OSINT signal, not proof. Always verify manually before
// acting, and only test domains you are authorized to assess.
package takeover

import (
	"context"
	"strings"

	"github.com/rahuljoshi/subscope/internal/dnsx"
	"github.com/rahuljoshi/subscope/internal/model"
)

// fingerprint maps a CNAME target suffix to the service that owns it.
type fingerprint struct {
	suffix  string
	service string
}

// Common SaaS CNAME targets that are frequent takeover candidates when dangling.
var fingerprints = []fingerprint{
	{".github.io", "GitHub Pages"},
	{".herokuapp.com", "Heroku"},
	{".herokudns.com", "Heroku"},
	{".s3.amazonaws.com", "AWS S3"},
	{".s3-website", "AWS S3"},
	{".cloudfront.net", "AWS CloudFront"},
	{".azurewebsites.net", "Azure App Service"},
	{".cloudapp.net", "Azure"},
	{".cloudapp.azure.com", "Azure"},
	{".trafficmanager.net", "Azure Traffic Manager"},
	{".blob.core.windows.net", "Azure Blob"},
	{".fastly.net", "Fastly"},
	{".ghost.io", "Ghost"},
	{".myshopify.com", "Shopify"},
	{".wordpress.com", "WordPress"},
	{".pantheonsite.io", "Pantheon"},
	{".zendesk.com", "Zendesk"},
	{".helpscoutdocs.com", "Help Scout"},
	{".readme.io", "Readme"},
	{".surge.sh", "Surge.sh"},
	{".bitbucket.io", "Bitbucket"},
	{".netlify.app", "Netlify"},
	{".netlify.com", "Netlify"},
	{".readthedocs.io", "Read the Docs"},
	{".statuspage.io", "Statuspage"},
	{".launchrock.com", "LaunchRock"},
	{".unbouncepages.com", "Unbounce"},
	{".desk.com", "Desk"},
	{".wpengine.com", "WP Engine"},
	{".tumblr.com", "Tumblr"},
	{".fly.dev", "Fly.io"},
	{".vercel.app", "Vercel"},
	{".pages.dev", "Cloudflare Pages"},
	{".firebaseapp.com", "Firebase"},
	{".web.app", "Firebase"},
}

// Check inspects rec for a dangling-CNAME takeover signal. It returns nil when
// there is nothing to report.
func Check(ctx context.Context, rec *model.Record, resolver *dnsx.Resolver) *model.TakeoverFinding {
	if len(rec.CNAME) == 0 {
		return nil
	}

	for _, cname := range rec.CNAME {
		target := strings.ToLower(strings.TrimSuffix(cname, "."))
		for _, fp := range fingerprints {
			if !strings.Contains(target, fp.suffix) {
				continue
			}
			// It points at a known service. Now: does the target resolve?
			// A dangling CNAME (target no longer exists) is the classic
			// takeover precondition.
			if !resolver.Exists(ctx, target) {
				return &model.TakeoverFinding{
					Vulnerable: true,
					Service:    fp.service,
					CNAME:      target,
					Reason:     "CNAME points to " + fp.service + " but the target does not resolve (dangling)",
				}
			}
			// Points at the service and resolves: note it, but not flagged.
			return &model.TakeoverFinding{
				Vulnerable: false,
				Service:    fp.service,
				CNAME:      target,
				Reason:     "CNAME points to " + fp.service + " (resolves; verify ownership of the target resource)",
			}
		}
	}
	return nil
}
