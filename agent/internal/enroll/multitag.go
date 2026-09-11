package enroll

// MultiTagger fans TagPID/UntagPID out to every wrapped tagger (enroll + enforcer maps).
type MultiTagger []KernelTagger

func (m MultiTagger) TagPID(pid uint32) error {
	for _, t := range m {
		if err := t.TagPID(pid); err != nil {
			return err
		}
	}
	return nil
}

func (m MultiTagger) UntagPID(pid uint32) error {
	for _, t := range m {
		if err := t.UntagPID(pid); err != nil {
			return err
		}
	}
	return nil
}
