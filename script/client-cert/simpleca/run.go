package simpleca

// BasicRun runs a basic CA setup.
func BasicRun(writeFiles bool) ([]*CA, error) {
	var cas []*CA

	// CA1
	{
		ca1, err := NewCA("ca1")
		if err != nil {
			return nil, err
		}

		client1, err := ca1.NewClient("client1", 41)
		if err != nil {
			return nil, err
		}
		_ = client1
		client2, err := ca1.NewClient("client2", 42)
		if err != nil {
			return nil, err
		}

		if err := ca1.RevokeClient(client2); err != nil {
			return nil, err
		}

		if writeFiles {
			if err := ca1.WriteFiles(); err != nil {
				return nil, err
			}
		}

		cas = append(cas, ca1)
	}

	// CA2
	{
		ca2, err := NewCA("ca2")
		if err != nil {
			return nil, err
		}

		client1, err := ca2.NewClient("client1", 41)
		if err != nil {
			return nil, err
		}
		_ = client1
		client2, err := ca2.NewClient("client2", 42)
		if err != nil {
			return nil, err
		}

		if err := ca2.RevokeClient(client2); err != nil {
			return nil, err
		}

		if writeFiles {
			if err := ca2.WriteFiles(); err != nil {
				return nil, err
			}
		}

		cas = append(cas, ca2)
	}

	return cas, nil
}
