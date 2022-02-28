
import falcon


n = 256
pubkey = "CCZVq4FwQD-uRROLPKD7tJUkW4yELVMcq7FVhDGnXbpiDEQ4uGp912nt9yGKcZFri2FldWHr6yV0R0USGc1HXIPq5YMtg-keJuX4Fl5QXsRQNggqVkjsCTBEacOiUlKz9NqXQtZVcSPRHSNgI_f0T_JtuBY4dxMuIFgdilQLUmX9V5soqyIYShlyeJnkABYNEhOB-IO-EZMBbaEvueWmJunDrHRmUq1Jarp8OUVqhfmoKZGlMN2oT4SqVTTZXZxkllu0FRQ1jJvD-qTOZDyISgmDXz3aiogqDwBFPsPYPmzdWBwcW5vuYV4o3GKr6bRpskZyoF-eLrgag5pR9nq6SlljG5kqguvKOEpFdv032gaOYrMJ9BGOmX9ZUdLUxMGZn9X_QhvnQmXAZAHGy6KafuI7_KMCB5zVQuBu0WLSYES4ZFWRdl6zaEXYVVwc4ORciJsSrska0wdNQPJ0VkoqfsF2Skla64PyGPlVp2pp8LqkbSRoOSA2oeYSYxny7Tp5b1wW4CNSmRG4fcIMkXzoJy3lNDDjLcMwJeXryBxjO-W1FxYiu25diWg-GQEGPtuRSgyqoipAgN6oqQIUd3NKohk"
privkey = "WABAvOiQzOAggfRQBPufRP_O_PtgCB9SPu_SuiNfthBTvf_ROwwQgOgwRBARyQPuff_ReSuwu__yvB__ABBAegd-gw_gAARv_OhAO0CxRRAziiAwQ-dxQvwPv_fADBBe_zShgPO-whyiCSfASfvwAAvQuBPxwfhvg-O-__hhee_QARAfhOygwfQAuxORRCBAPOu_ABeOef9BBQQNP9PuBAgPRRSxPQgyRCvfvhx_RQB_N_cv-x-jvQyR-wQxCgQv_AP-vffQeAew_eQA7--wtv-gA-vyweyPOgg_OQAPNAwPdhvA9RvhBBuQNyOvBOvuhRuQBhBQ_dvh9vvAixPBSeiQBwgwAbwAQuBwwxATSgOhufQReQAtvugAzOSft_ABw_huuvSkfuyABCR-hAffwRuQfCAhCAvRAf_wfRCAfwfiu9gQAgRe_PBP_QhPwPhfAgthRPQPeAQfhgdfSDewQ_ABhizx-hNOu-hfOvgPfOBvxygxwxNeOe-vQfR_QQQPgA_65_kd8-MT_vwYB9j1zfnWIQgI-_3-BRXFDt87Bgf8AhLaECX4_ekEAgHJ-QwEDPERFtn6Mv0H6jLdFg0J3-wCAtof1wbs9-ba8uMGBC3j0ufmDegz8wfpDtTWBS0M7gcZCiT6BwAC6BAECucBEg4MAArW-dwAzvq69AYGAC8lBPbaCAcUKAEa2fYbExcCHPQkGv4i4vfN_QQi7xLWEv79_Snu8OoG6BfxABEaFhwMTw7iEdf2Bw3f0OPDEPQzwxb3FfP44iIaHxwzAvYLHxIK9ucAyRDaJf721gvQJPIGCRTS-fsdT9cd__MC-P7_BfoYEuju9wIeD_wRyPoHDwU"
message = "This is a test message"
signature = "OBW7Kz_uUEUj0sV9A2FHY8yYAK1EnG_63WK-xv7H5KJOmCo25XI2nh0Y0cEk8UzOtTD6IT_Cx5Nn-tvXdYFs3VnZ-sNufE3g6SJIyeAyHJzxylqu3ISA4bQ3ys_ipmQhZVZNDuP-8iwXEcFRcvmi0OBfIqzCBqDUcFsUHoG54dhdRfEcvqavhnmqkL5w_EsWRSDZqsahFZihEW0XdoFo_lvsVXqFd75PpC0je7h-ZpS5IjhAK1FshBJSw5TXjJGtWBk6gDOxV90npk29MZpJOpuo_m-DrWKSxa2Yju0o-9JTpsKEy95TNSqhXXttVFYWAyVYme0EVi6MnOhlFvOFvf77S2Qlb3s0EMtqyELgzTs4sqdsN-p24cngZiiFtkar6nyrkqlv_i9udnvI0o_7UKEYJFlzxGWaumSGN95CzZMrNmHxbY-XNVzrQ9YJ0jW7qVE-lN3N23HggA"

import base64

class ExternalPublicKey(falcon.SecretKey):
	"""
	This class contains methods for performing external public key operations in Falcon.
	"""

	def __init__(self, pubkey):
		"""Initialize an external public key."""
		# Convert from Base64
		pubkey = pubkey.encode()
		pubkey = base64.urlsafe_b64decode((pubkey.decode() + ('=' * (4 - (len(pubkey) % 4)))).encode())
		# Extract logn & n
		logn = (pubkey[0] & 0x0F)
		n = 2 ** logn
		# Extract h
		self.h = []
		v = self.decode_h(self.h, logn, pubkey[1:])
		if v == 0:
			raise NameError('Failed to decode h')

		self.n = n
		self.sigma = falcon.Params[n]["sigma"]
		self.sigmin = falcon.Params[n]["sigmin"]
		self.signature_bound = falcon.Params[n]["sig_bound"]
		self.sig_bytelen = falcon.Params[n]["sig_bytelen"]


	def __repr__(self):
		"""Print the object in readable form."""
		rep = "External Public for n = {n}:\n\n".format(n=self.n)
		rep += "h = {h}\n".format(h=self.h)
		return rep

	def verifyBase64(self, message, signature):
		signature = signature.encode()
		signature = base64.urlsafe_b64decode((signature.decode() + ('=' * (4 - (len(signature) % 4)))).encode())
		return self.verify(message.encode(), signature)
	
	def decode_h(self, x, logn, buf):
		# based on modq_decode
		n = 1 << logn
		in_len = ((n * 14) + 7) >> 3;
		
		if in_len > len(buf):
			return 0
		
		acc = 0
		acc_len = 0
		u = 0
		while (len(x) < n):
			acc = (acc << 8) | buf[u]
			u += 1
			acc_len += 8
			if acc_len >= 14:
				acc_len -= 14;
				w = (acc >> acc_len) & ((1 << 14) - 1);
				if w >= 12289:
					return 0
				x.append(w)
		if (acc & ((1 << acc_len) - 1)) != 0:
				print(acc & (1 << acc_len) - 1)
				return 0
		return in_len


print("Testing ------------------------------")
pubkey = ExternalPublicKey(pubkey)
print(pubkey)
v = pubkey.verifyBase64(message, signature)
print(v)

