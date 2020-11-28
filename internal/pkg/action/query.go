package action

import "fleet/internal/pkg/dsl"

const (
	SeqNo      = "_seq_no"
	Expiration = "expiration"
	Agents     = "agents"
)

type SearchQuery struct {
	tmpl *dsl.Tmpl

	tokenSeqNo, tokenExpiration, tokenAgents dsl.Token
}

type SearchOptFunc func(*SearchQuery)

func WithSeqNo() SearchOptFunc {
	return func(q *SearchQuery) {
		q.tokenSeqNo = q.tmpl.Bind(SeqNo)
	}
}

func WithExpiration() SearchOptFunc {
	return func(q *SearchQuery) {
		q.tokenExpiration = q.tmpl.Bind(Expiration)
	}
}

func WithAgents() SearchOptFunc {
	return func(q *SearchQuery) {
		q.tokenAgents = q.tmpl.Bind(Agents)
	}
}

func NewSearchQuery(opts ...SearchOptFunc) (*SearchQuery, error) {
	q := &SearchQuery{
		tmpl: dsl.NewTmpl(),
	}

	for _, opt := range opts {
		opt(q)
	}

	root := dsl.NewRoot()
	root.Param("seq_no_primary_term", true)

	if q.tokenSeqNo != "" || q.tokenExpiration != "" || q.tokenAgents != "" {
		filterNode := root.Query().Bool().Filter()
		if q.tokenSeqNo != "" {
			filterNode.Range(SeqNo, dsl.WithRangeGT(q.tokenSeqNo))
		}
		if q.tokenExpiration != "" {
			filterNode.Range(Expiration, dsl.WithRangeGT(q.tokenExpiration))
		}
		if q.tokenAgents != "" {
			filterNode.Terms(Agents, q.tokenAgents, nil)
		}
	}

	root.Sort().SortOrder(SeqNo, dsl.SortAscend)

	if err := q.tmpl.Resolve(root); err != nil {
		return nil, err
	}

	return q, nil
}

func (q *SearchQuery) Render(m map[string]interface{}) ([]byte, error) {
	return q.tmpl.Render(m)
}
