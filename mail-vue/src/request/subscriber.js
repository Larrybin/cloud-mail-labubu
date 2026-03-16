import http from '@/axios/index.js'
import { useSettingStore } from '@/store/setting.js'

export function subscriberList(params) {
	return http.get('/subscriber/list', { params: { ...params }, noMsg: true })
}

export async function subscriberExport(params) {
	const { lang } = useSettingStore()
	const search = new URLSearchParams()

	Object.entries(params || {}).forEach(([key, value]) => {
		if (value === undefined || value === null || value === '') return
		if (key === 'page' || key === 'size') return
		search.set(key, value)
	})
	search.set('page', '1')
	search.set('size', '5000')

	const response = await fetch(
		`${import.meta.env.VITE_BASE_URL}/subscriber/export?${search.toString()}`,
		{
			headers: {
				Authorization: `${localStorage.getItem('token') || ''}`,
				'accept-language': lang
			}
		},
	)

	if (!response.ok) {
		throw new Error('export failed')
	}

	return await response.blob()
}
